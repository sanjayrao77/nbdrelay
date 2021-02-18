/*
 * main.c - entry, options and top process loop
 * Copyright (C) 2021 Sanjay Rao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <syslog.h>
#include <sys/wait.h>
#include <sys/socket.h>
#ifndef DEBUG
#define DEBUG
#endif
#include "common/conventions.h"
#include "misc.h"
#include "options.h"
#include "kernel.h"
#include "relay.h"
#include "mounts.h"
#include "sigproc.h"

#include "main.h"

int isquit_global,ishup_global;

void term_handler(int ign) {
isquit_global=1;
}
void hup_handler(int ign) {
ishup_global=1;
}
void chld_handler(int ign) {
}

static int readu64(uint64_t *u_out, int fd) {
uint64_t u;
if (readn(fd,(unsigned char *)&u,sizeof(u))) return -1;
*u_out=u;
return 0;
}
static int s_readu64(uint64_t *u_out, int fd, struct tracking_kernel *tk) {
fd_set rset;
while (1) {
	FD_ZERO(&rset);
	FD_SET(fd,&rset);
	switch (select(fd+1,&rset,NULL,NULL,NULL)) {
		case 1: return readu64(u_out,fd);
		case -1:
			if (!tk->isalive) return -1;
			if (errno!=EINTR) GOTOERROR;
	}
}
return 0;
error:
	return -1;
}

static int getoptions(struct options *options, int argc, char **argv) {
while (argc) {
	char *arg;
	arg=*argv;
	argc--;
	argv++;
	if (arg[0]!='-') {
		if (!strncmp(arg,"nbd://",6) || !strncmp(arg,"nbd-tls://",10) || !strncmp(arg,"file://",7)) options->url=arg;
		else options->device=arg;
	} else if (!strcmp(arg,"-verbose")) {
		options->isverbose=1;
	} else if (!strcmp(arg,"-verifycert")) {
		options->isverifycert=1;
	} else if (!strcmp(arg,"-debug")) {
		options->isdebug=1;
	} else if (!strcmp(arg,"-stdin")) {
		options->isstdin=1;
	} else if (!strcmp(arg,"-write")) {
		options->iswrite=1;
	} else if (!strcmp(arg,"-d")) {
		options->isdisconnect=1;
	} else if (!strcmp(arg,"-rebuild")) {
		options->isrebuild=1;
	} else if (!strcmp(arg,"-remount")) {
		options->isremount=1;
	} else {
		char *arg2;
		if (!argc) { fprintf(stdout,"Ignoring argument %s\n",arg); break; }
		arg2=*argv;
		if (!strcmp(arg,"-shorttimeout")) {
			options->shorttimeout=atou32(arg2);
			argv++;argc--;
		} else if (!strcmp(arg,"-longtimeout")) {
			options->longtimeout=atou32(arg2);
			argv++;argc--;
		} else if (!strcmp(arg,"-user")) {
			options->str_user=arg2;
			argv++;argc--;
		} else if (!strcmp(arg,"-group")) {
			options->str_group=arg2;
			argv++;argc--;
		} else if (!strcmp(arg,"-mount")) {
			options->mount=arg2;
			argv++;argc--;
		} else if (!strcmp(arg,"-certfile")) {
			options->certfile=arg2;
			argv++;argc--;
		} else if (!strcmp(arg,"-keyfile")) {
			options->keyfile=arg2;
			argv++;argc--;
		} else if (!strcmp(arg,"-exportsize")) {
			options->exportsize=atou64(arg2);
			argv++;argc--;
		} else {
			fprintf(stdout,"Ignoring argument %s\n",arg);
		}
	
	}
	
}
return 0;
}

static int closestds(void) {
int fd;
if (0>(fd=open("/dev/null",O_RDWR))) GOTOERROR;
if (0>dup2(fd,STDIN_FILENO)) GOTOERROR;
if (0>dup2(fd,STDOUT_FILENO)) GOTOERROR;
if (0>dup2(fd,STDERR_FILENO)) GOTOERROR;
return 0;
error:
	return -1;
}

SICLEARFUNC(options);
int main(int argc, char **argv) {
struct options options;
int sv[2]={-1,-1};
int pv[2]={-1,-1};
int dv[2]={-1,-1};
pid_t relaypid=-1;
struct tracking_kernel tk;

clear_options(&options);
clear_tracking_kernel(&tk);

(void)openlog(NULL,LOG_PERROR|LOG_PID,LOG_USER);
if (SIG_ERR==signal(SIGTERM,term_handler)) GOTOERROR;
if (SIG_ERR==signal(SIGHUP,hup_handler)) GOTOERROR;
if (SIG_ERR==signal(SIGCHLD,chld_handler)) GOTOERROR;

#if 0
options.isverbose=1;
options.shorttimeout=30;
options.url="nbd://ftl/example"; // nbd-tls:// and file:///home/me/example.fs
options.str_user="nobody";
options.str_group="nogroup";
#endif

options.shorttimeout=10;
options.longtimeout=600;
options.str_user="nobody";
options.str_group="nogroup";
options.device="/dev/nbd0";

if (argc) {
	if (getoptions(&options,argc-1,argv+1)) GOTOERROR;
}

if (options.isdisconnect) {
	if (disconnect_kernel(&options,0)) {
		fprintf(stderr,"Error disconnecting %s\n",options.device);
	}
	return 0;
}

(void)closelog();
(void)openlog(NULL,(options.isdebug)?LOG_PERROR|LOG_PID:LOG_PID,(options.isdebug)?LOG_USER:LOG_DAEMON);

if (options.isstdin) {
#define MAXURL	200
	char *temp;
	int lenleft=MAXURL;
	if (!(temp = options.tofree.url = malloc(MAXURL+9))) GOTOERROR; // extra bytes for ]_rebuild
	if (options.url) {
		int len;
		len=strlen(options.url);
		memcpy(temp,options.url,len);
		temp+=len;
		lenleft-=len;
	}
	options.url=options.tofree.url;
	if (!fgets(temp,lenleft,stdin)) {
		syslog(LOG_ERR,"No stdin input and -stdin specified.");
		GOTOERROR;
	}
	temp=strchr(temp,'\n');
	if (temp) *temp='\0';
}

if (options.isremount) {
	options.istryunmount=1;
	if (umount_mounts(&options)) {
		fprintf(stderr,"Error unmounting %s\n",options.mount);
		return 0;
	}
	fprintf(stderr,"Unmounted. Sleeping 5 seconds before remount.\n");
	sleep(5); // this is to accommodate a kernel issue
	if (killsisters_sigproc(getpid(),SIGHUP)) {
		fprintf(stderr,"Error signaling other processes\n");
	}
	return 0;
}

if (!options.url) {
	fprintf(stdout,
"Usage: nbd-client-relay [-verbose] [-verifycert] [-debug] [-stdin]\n"\
"[-write] [-rebuild] [-exportsize BYTESIZE] [-shorttimeout SECONDS]\n"\
"[-longtimeout SECONDS] [-user USER] [-group GROUP] [-mount PATH]\n"\
"[-certfile FILENAME] [-keyfile FILENAME] [URL] [-d] [BLOCKDEVICE]\n"\
"\n"\
"URL can be of the form nbd://hostname:port/export,\n"\
"nbd-tls://hostname:port/export, or file://fullpath\n"\
"\n");
	return 0;
}

if (options.isrebuild) { // this is for psqfs-nbd-server
	int len;
	if (options.tofree.url) {
		len=strlen(options.tofree.url);
	} else {
		len=strlen(options.url);
		if (!(options.tofree.url=malloc(len+9+1))) GOTOERROR;
		memcpy(options.tofree.url,options.url,len);
		options.url=options.tofree.url;
	}
	memcpy(options.url+len,"]_rebuild",9+1);
	options.exportsize=0;
}

if (options.str_user) {
	if (getuid_misc(&options.user,options.str_user)) GOTOERROR;
}
if (options.str_group) {
	if (getgid_misc(&options.group,options.str_group)) GOTOERROR;
}

if (!options.isdebug) {
	pid_t pid;
//	if (daemon(0,0)) GOTOERROR; // we want to hold off returning until after device is configured
	if (chdir("/")) GOTOERROR;
	if (closestds()) GOTOERROR;
	if (pipe(dv)) GOTOERROR;
	pid=fork();
	if (pid<0) GOTOERROR;
	if (pid) {
		char ign;
		(ignore)close(dv[1]);
		(ignore)read(dv[0],&ign,1);
		_exit(0);
	}
	(ignore)close(dv[0]); dv[0]=-1;
}

while (!isquit_global) {
	uint64_t size,ign;
	int i;
	if (isdevice_misc(&i,options.device)) GOTOERROR;
	if (i) {
		syslog(LOG_ERR,"Error: device %s is already present",options.device);
		GOTOERROR;
	}
	if (pipe(pv)) GOTOERROR;
	if (socketpair(AF_LOCAL,SOCK_STREAM,0,sv)) GOTOERROR;

	if (fork_relay(&relaypid,sv[0],sv[1],pv[1],&options)) GOTOERROR; // closes sv[1] in fork
	close(sv[0]); sv[0]=-1;
	close(pv[1]); pv[1]=-1;
	if (readu64(&size,pv[0])) GOTOERROR;
//	if (fork_kernel(&tk,sv[1],size,&options)) GOTOERROR;
	if (thread_kernel(&tk,sv[1],size,&options)) GOTOERROR; // sv[1] stays alive, we keep it open for kernel wrap-up after DO_IT
	if (s_readu64(&ign,pv[0],&tk)) {
		if (tk.isalive) {
			syslog(LOG_ERR,"Error configuring kernel, giving up");
			(void)wait_kernel(&tk);
			break;
		}
		GOTOERROR;
	}
	(ignore)close(pv[0]); pv[0]=-1;

	if (mount_mounts(&options)) GOTOERROR;
	if (dv[1]!=-1) { // tell parent (if any) to exit
		char ch=0;
		(ignore)write(dv[1],&ch,1);
		(ignore)close(dv[1]); dv[1]=-1;
	}

	while (!isquit_global) {
		pid_t p;
		int status;
		pause();
		p=waitpid(relaypid,&status,WNOHANG);
		if (p==relaypid) {
			relaypid=-1;
			if (WIFEXITED(status) && (WEXITSTATUS(status)==101)) ishup_global=1;
			else goto doublebreak;
		}
		if (ishup_global) {
			int isfirst=1;

			ishup_global=0;
			while (1) {
				if (!umount_mounts(&options)) break;
				sleep(1);
				if (!isfirst) continue;
				syslog(LOG_INFO,"Error unmounting %s, still trying",options.mount);
				isfirst=0;
			}
			if (disconnect_kernel(&options,0)) GOTOERROR;
			(void)wait_kernel(&tk);
			if (relaypid!=-1) while (relaypid!=waitpid(relaypid,NULL,0)) sleep(1);
			relaypid=-1;
			break;
		}
	}
	(ignore)close(sv[1]); sv[1]=-1;
}
doublebreak:
if (umount_mounts(&options)) GOTOERROR;
if (tk.isvalid) {
	if (disconnect_kernel(&options,0)) GOTOERROR;
	(void)wait_kernel(&tk);
	if (relaypid!=-1) while (relaypid!=waitpid(relaypid,NULL,0)) sleep(1);
}
if (disconnect_kernel(&options,1)) GOTOERROR;

ifclose(sv[1]);
return 0;
error:
	(void)wait_kernel(&tk); // pthread_create wants tk to be valid
	ifclose(sv[0]);
	ifclose(sv[1]);
	ifclose(pv[0]);
	ifclose(pv[1]);
	ifclose(dv[0]);
	ifclose(dv[1]);
	return -1;
}
