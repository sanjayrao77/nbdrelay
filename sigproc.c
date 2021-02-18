/*
 * sigproc.c - signal sister processes
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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <inttypes.h>
#include "common/conventions.h"
#include "sigproc.h"

static uint64_t slowto64(char *str) {
uint64_t ret=0;
switch (*str) {
	case '1': ret=1; break;
	case '2': ret=2; break;
	case '3': ret=3; break;
	case '4': ret=4; break;
	case '5': ret=5; break;
	case '6': ret=6; break;
	case '7': ret=7; break;
	case '8': ret=8; break;
	case '9': ret=9; break;
	case '+':
	case '0': break;
	default: return 0; break;
}
while (1) {
	str++;
	switch (*str) {
		case '9': ret=ret*10+9; break;
		case '8': ret=ret*10+8; break;
		case '7': ret=ret*10+7; break;
		case '6': ret=ret*10+6; break;
		case '5': ret=ret*10+5; break;
		case '4': ret=ret*10+4; break;
		case '3': ret=ret*10+3; break;
		case '2': ret=ret*10+2; break;
		case '1': ret=ret*10+1; break;
		case '0': ret=ret*10; break;
		default: return ret; break;
	}
}
return ret;
}

int kill_sigproc(char *linkpath, int linkn, pid_t ignpid, int sig) {
char onepath[128];
DIR *dir=NULL;

if (!(dir=opendir("/proc"))) GOTOERROR;
while (1) {
	struct dirent *de;
	char dlink[128];
	char spid[20+1];
	pid_t dpid;
	int r;
	errno=0;
	if (!(de=readdir(dir))) break;
	if (de->d_type!=DT_DIR) continue;
	r=snprintf(onepath,128,"/proc/%s/exe",de->d_name);
	if ((r<0)||(r>128)) continue;
	r=readlink(onepath,dlink,128);
	if (r!=linkn) continue;
	if (memcmp(dlink,linkpath,linkn)) continue;
	dpid=slowto64(de->d_name);
	if (dpid==ignpid) continue;
	snprintf(spid,21,"%"PRIu64,(uint64_t)dpid);
	if (strcmp(spid,de->d_name)) continue;
	(ignore)kill(dpid,sig);
}
if (errno) GOTOERROR;
closedir(dir);
return 0;
error:
	if (dir) closedir(dir);
	return -1;
}

int killsisters_sigproc(pid_t pid, int sig) {
// TODO could use readlinkat("") to remove intermediary onepath[]
char onepath[128];
char linkpath[128];
int linkn;

snprintf(onepath,128,"/proc/%u/exe",pid);
linkn=readlink(onepath,linkpath,128);
if (linkn<0) GOTOERROR;
if (linkn==128) GOTOERROR;

return kill_sigproc(linkpath,linkn,pid,sig);
error:
	return -1;
}
