/*
 * relay.c - main loop
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
#include <errno.h>
#include <syslog.h>
#include <linux/nbd.h>
#include "common/conventions.h"
#include "fileio.h"
#include "nbdclient.h"
#ifdef HAVETLS
#include <gnutls/gnutls.h>
#include "nbdtlsclient.h"
#endif
#include "unionio.h"
#include "misc.h"
#include "options.h"
#include "growbuff.h"
#include "main.h"

#include "relay.h"

#define getu16(a) be16toh(*(uint16_t*)(a))
#define getu32(a)	be32toh(*(uint32_t*)(a))
#define getu64(a) be64toh(*(uint64_t*)(a))
#define setu16(a,b) *(uint16_t*)(a)=htobe16(b)
#define setu32(a,b) *(uint32_t*)(a)=htobe32(b)
#define setu64(a,b) *(uint64_t*)(a)=htobe64(b)

static int writeu64(int fd, uint64_t u) {
return writen(fd,(unsigned char *)&u,sizeof(u));
}

static int waitforread(int fd) {
fd_set rset;
while (1) {
	FD_ZERO(&rset);
	FD_SET(fd,&rset);
	switch (select(fd+1,&rset,NULL,NULL,NULL)) {
		case -1: if (errno!=EINTR) return -1;
		case 0: continue;
		default: return 0;
	}
}
}

static int nbd_cmd_read(int kfd, struct unionio *io, unsigned char *cmd28, struct growbuff *gb) {
unsigned char reply[16];
uint64_t offset;
uint32_t count;
unsigned char *buff;

offset=getu64(cmd28+16);
count=getu32(cmd28+24);
if (!count) GOTOERROR;

// fprintf(stderr,"Got READ from kernel %"PRIu64".%u\n",offset,count);

if (!(buff=fetch_growbuff(gb,count))) GOTOERROR;
while (readoff_unionio(io,buff,offset,count)) {
	if (io->isunrecoverable) GOTOERROR;
	if (io->iserror) sleep(59);
	sleep(1);
	if (isquit_global) return 0;
}

#define NBD_SIMPLE_REPLY_MAGIC			(0x67446698)
setu32(reply,NBD_SIMPLE_REPLY_MAGIC);
setu32(reply+4,0);
memcpy(reply+8,cmd28+8,8); // handle
if (writen(kfd,reply,16)) GOTOERROR;
if (writen(kfd,buff,count)) GOTOERROR;

return 0;
error:
	return -1;
}

static int nbd_cmd_write(int kfd, struct unionio *io, unsigned char *cmd28, struct growbuff *gb) {
unsigned char reply[16];
uint64_t offset;
uint32_t count;
unsigned char *buff;
unsigned int flags;
int isfua;

flags=getu16(cmd28+4);
offset=getu64(cmd28+16);
count=getu32(cmd28+24);
if (!count) GOTOERROR;

// fprintf(stderr,"Got WRITE from kernel %"PRIu64".%u\n",offset,count);

isfua=flags&NBD_CMD_FLAG_FUA;

if (!(buff=fetch_growbuff(gb,count))) GOTOERROR;
if (readn(kfd,buff,count)) GOTOERROR;

while (writeoff_unionio(io,buff,offset,count,isfua)) {
	if (io->isunrecoverable) GOTOERROR;
	if (io->iserror) sleep(59);
	sleep(1);
	if (isquit_global) return 0;
}

setu32(reply,NBD_SIMPLE_REPLY_MAGIC);
setu32(reply+4,0);
memcpy(reply+8,cmd28+8,8); // handle
if (writen(kfd,reply,16)) GOTOERROR;

return 0;
error:
	return -1;
}

static int nbd_cmd_trim(int kfd, struct unionio *io, unsigned char *cmd28) {
unsigned char reply[16];
uint64_t offset;
uint32_t count;

offset=getu64(cmd28+16);
count=getu32(cmd28+24);
if (!count) GOTOERROR;

// fprintf(stderr,"Got TRIM from kernel %"PRIu64".%u\n",offset,count);

while (trim_unionio(io,offset,count)) {
	if (io->isunrecoverable) GOTOERROR;
	if (io->iserror) sleep(59);
	sleep(1);
	if (isquit_global) return 0;
}

setu32(reply,NBD_SIMPLE_REPLY_MAGIC);
setu32(reply+4,0);
memcpy(reply+8,cmd28+8,8); // handle
if (writen(kfd,reply,16)) GOTOERROR;

return 0;
error:
	return -1;
}

static int nbd_cmd_flush(int kfd, struct unionio *io, unsigned char *cmd28) {
unsigned char reply[16];

// fprintf(stderr,"Got FLUSH from kernel %"PRIu64".%u\n",offset,count);

while (flush_unionio(io)) {
	if (io->isunrecoverable) GOTOERROR;
	if (io->iserror) sleep(59);
	sleep(1);
	if (isquit_global) return 0;
}

setu32(reply,NBD_SIMPLE_REPLY_MAGIC);
setu32(reply+4,0);
memcpy(reply+8,cmd28+8,8); // handle
if (writen(kfd,reply,16)) GOTOERROR;

return 0;
error:
	return -1;
}

static int mainloop(int kfd, struct unionio *io, struct growbuff *gb) {
unsigned char buffer[28];

while (!isquit_global) {
	fd_set rset;
	FD_ZERO(&rset);
	FD_SET(kfd,&rset);
	if (-1==select(kfd+1,&rset,NULL,NULL,NULL)) {
		if (errno==EINTR) continue;
		GOTOERROR;
	}
	if (readn(kfd,buffer,28)) GOTOERROR;
// #define NBD_REQUEST_MAGIC					(0x25609513)
// #define NBD_CMD_READ								(0)
// #define NBD_CMD_DISC								(2)
	if (getu32(buffer)!=NBD_REQUEST_MAGIC) GOTOERROR;
	switch (getu16(buffer+6)) {
		case NBD_CMD_READ:
			if (nbd_cmd_read(kfd,io,buffer,gb)) GOTOERROR;
			break;
		case NBD_CMD_WRITE:
			if (nbd_cmd_write(kfd,io,buffer,gb)) GOTOERROR;
			break;
		case NBD_CMD_TRIM:
			if (nbd_cmd_trim(kfd,io,buffer)) GOTOERROR;
			break;
		case NBD_CMD_FLUSH:
			if (nbd_cmd_flush(kfd,io,buffer)) GOTOERROR;
			break;
		case NBD_CMD_DISC: 
			(ignore)shutdown_unionio(io);
			goto doublebreak;
	}
}
doublebreak:
return 0;
error:
	return -1;
}



SICLEARFUNC(growbuff);
static int runrelay(int sock, int wfd, struct options *options) {
struct unionio unionio;
struct growbuff growbuff;
int isretry=0;

clear_unionio(&unionio);
clear_growbuff(&growbuff);

if (options->group) {
	if (setgid(options->group)) {
		syslog(LOG_ERR,"Error setting group");
		GOTOERROR;
	}
}
if (options->user) {
	if (setuid(options->user)) {
		syslog(LOG_ERR,"Error setting user");
		GOTOERROR;
	}
}

if (init_unionio(&unionio,options->iswrite,options->isdebug,options->url,options->shorttimeout,
		options->certfile,options->keyfile,options->isverifycert)) GOTOERROR;

{
	int seconds=1,fuse=30;
	int isfirst=1;
	if (options->exportsize) {
		unionio.orig_size = unionio.size = options->exportsize;
	} else while (1) { // we need the device size before we register with kernel
		if (connect_unionio(&unionio)) {
			if (unionio.isunrecoverable) {
				if (unionio.isroviolation) syslog(LOG_ERR,"Source doesn't allow write, disconnecting");
				else syslog(LOG_ERR,"Unrecoverable error connecting to source.");
				GOTOERROR;
			}
			if (isfirst) {
				isfirst=0;
				if (options->isdebug) fprintf(stderr,"Error connecting to source, retrying...\n");
			}
		}
		if (unionio.isconnected) {
			if (options->iswrite && isreadonly_unionio(&unionio)) {
				syslog(LOG_ERR,"Source is read-only, quitting");
				GOTOERROR;
			}
			if (options->isrebuild) {
				(void)removetail_unionio(&unionio,(unsigned char *)"]_rebuild",9);
#if 0
				int len;
				options.isrebuild=0;
				(ignore)shutdown_unionio(&unionio);
				len=strlen(options.url);
				options.url[len-9]='\0'; // 9:]_rebuild
				if (reinit_unionio(&unionio,options.isdebug,options.url,options.shorttimeout,
						options.certfile,options.keyfile,options.isverifycert)) GOTOERROR;
				continue;
#endif
			}
			unionio.orig_size=unionio.size;
			break;
		}
		sleep(seconds);
		fuse--; if (!fuse && (seconds<10)) { seconds*=2; fuse=30; }
	}
}

if (writeu64(wfd,unionio.orig_size)) GOTOERROR;
if (waitforread(sock)) GOTOERROR; // kernel is alive
if (writeu64(wfd,0)) GOTOERROR; // tell parent kernel is alive
close(wfd); wfd=-1;

if (mainloop(sock,&unionio,&growbuff)) {
	if (unionio.isroviolation) {
		syslog(LOG_ERR,"Source doesn't allow write, disconnecting");
	} else if (unionio.isresize) {
		syslog(LOG_ERR,"Source changed size underneath us, disconnecting");
		isretry=1;
	} else if (unionio.isnametoolong) {
		syslog(LOG_ERR,"Canon name is too long to store");
	} else if (unionio.isnamechange) {
		if (options->isverbose) syslog(LOG_INFO,"Canon name has changed name: %s",unionio.badcanon);
		isretry=1;
	} else {
		syslog(LOG_ERR,"Error encountered, disconnecting");
		GOTOERROR;
	}
}
deinit_growbuff(&growbuff);
deinit_unionio(&unionio);
if (isretry) return 101; // have parent simulate HUP
return 0;
error:
	deinit_growbuff(&growbuff);
	deinit_unionio(&unionio);
	return -1;
}

int fork_relay(int *pid_out, int k_sock, int u_sock, int wfd, struct options *options) {
pid_t pid;

pid=fork();
if (pid<0) GOTOERROR;
if (!pid) {
	(ignore)close(u_sock);
	if (runrelay(k_sock,wfd,options)) _exit(1);
	_exit(0);
}
*pid_out=pid;
return 0;
error:
	return -1;
}

