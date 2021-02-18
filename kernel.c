/*
 * kernel.c - interface for kernel's NBD driver
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
#include <syslog.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <linux/nbd.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "common/conventions.h"
#include "options.h"
#include "mounts.h"

#include "kernel.h"

static int doit_kernel(int sock, uint64_t size64, struct options *options) {
unsigned long one=1;
unsigned long blocksize=4096;
unsigned long blockcount;
unsigned long flags;
int fd=-1;
int r;

// #define NBD_FLAG_HAS_FLAGS					(1<<0)
// #define NBD_FLAG_READ_ONLY					(1<<1)
flags=NBD_FLAG_HAS_FLAGS|NBD_FLAG_SEND_FLUSH|NBD_FLAG_SEND_TRIM|NBD_FLAG_SEND_FUA;
if (!options->iswrite) flags|=NBD_FLAG_READ_ONLY;

fd=open(options->device,O_RDONLY);
if (fd<0) {
	syslog(LOG_ERR,"Unable to open device %s. Is nbd module loaded?",options->device);
	GOTOERROR;
}

blockcount=size64/blocksize;
// syslog(LOG_INFO,"Trying blocksize: %lu blockcount: %lu",blocksize,blockcount);
if (0>ioctl(fd,NBD_SET_BLKSIZE,blocksize)) {
	syslog(LOG_ERR,"Error setting blocksize %lu for device %s",blocksize,options->device);
	GOTOERROR;
}
if (0>ioctl(fd,NBD_SET_SIZE_BLOCKS,blockcount)) GOTOERROR;
if (0>ioctl(fd,NBD_CLEAR_SOCK)) GOTOERROR;
if (0>ioctl(fd,NBD_SET_FLAGS,(unsigned long)flags)) GOTOERROR;
if (flags&NBD_FLAG_READ_ONLY) {
	if (0>ioctl(fd,BLKROSET,&one)) GOTOERROR;
}
if (0>ioctl(fd,NBD_SET_SOCK,sock)) GOTOERROR;
r=ioctl(fd,NBD_DO_IT);
if (0>ioctl(fd,NBD_CLEAR_SOCK)) GOTOERROR;
if (r) {
	syslog(LOG_ERR,"Error in NBD_DO_IT: %s",strerror(errno));
	GOTOERROR;
}

(ignore)close(fd);
return 0;
error:
	ifclose(fd);
	return -1;
}

int disconnect_kernel(struct options *options, int isclear) {
int fd=-1;

if (isclear) { // don't want to lose data if mounted rw, we _could_ check to see if is readonly
	int isfound;
	if (dev_ismounted_mounts(&isfound,options->device)) GOTOERROR;
	if (isfound) {
		syslog(LOG_ERR,"Device %s is mounted. Disconnect request is ignored.",options->device);
		return -1;
	}
}

fd=open(options->device,O_RDONLY);
if (fd<0) {
	syslog(LOG_ERR,"Unable to open device %s. Is nbd module loaded?",options->device);
	GOTOERROR;
}
if (0>ioctl(fd,NBD_DISCONNECT)) GOTOERROR;
if (isclear) {
	if (0>ioctl(fd,NBD_CLEAR_SOCK)) GOTOERROR;
}
(ignore)close(fd);
return 0;
error:
	ifclose(fd);
	return -1;
}

#if 0
// fork version (no pthreads)
void clear_tracking_kernel(struct tracking_kernel *tk) {
tk->pid=-1;
}

int fork_kernel(struct tracking_kernel *tracking, int sock, uint64_t size, struct options *options) {
pid_t pid;

pid=fork();
if (!pid) {
	if (doit_kernel(sock,size,options)) _exit(1);
	_exit(0);
}
if (pid<0) GOTOERROR;
tracking->pid=pid;
return 0;
error:
	return -1;
}

void wait_kernel(struct tracking_kernel *tk) {
if (tk->pid==-1) return;
while (tk->pid!=waitpid(tk->pid,NULL,0)) sleep(1);
tk->pid=-1;
}
#endif


#if 1
// pthreads version
static void cleanup(void *params) {
struct tracking_kernel *tracking=(struct tracking_kernel *)params;
tracking->isalive=0;
(ignore)raise(SIGUSR1);
}
static void *threadstart(void *params) {
struct tracking_kernel *tracking=(struct tracking_kernel *)params;
sigset_t ss;
(ignore)sigemptyset(&ss);
(ignore)sigaddset(&ss,SIGHUP);
(ignore)sigaddset(&ss,SIGTERM);
(ignore)pthread_sigmask(SIG_BLOCK,&ss,NULL);
tracking->isalive=1; // volatile
pthread_cleanup_push(cleanup,params);
	(ignore)doit_kernel(tracking->params.sock,tracking->params.size,tracking->params.options);
pthread_cleanup_pop(0);
return NULL;
}

CLEARFUNC(tracking_kernel);
int thread_kernel(struct tracking_kernel *tracking, int sock, uint64_t size, struct options *options) {
// .tracking should be valid for the lifetime of the thread
tracking->params.sock=sock;
tracking->params.size=size;
tracking->params.options=options;
if (pthread_create(&tracking->pthread,NULL,threadstart,(void *)tracking)) GOTOERROR;
tracking->isvalid=1;
tracking->isjoinable=1;
return 0;
error:
	return -1;
}

void wait_kernel(struct tracking_kernel *tk) {
if (!tk->isvalid) return;
if (tk->isjoinable) (ignore)pthread_join(tk->pthread,NULL);
tk->isjoinable=0;
tk->isalive=0;
tk->isvalid=0;
}
#endif
