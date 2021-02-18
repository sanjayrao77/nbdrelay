/*
 * mounts.c - handle mounting and unmounting
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
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <wait.h>
#include <fcntl.h>
#include <syslog.h>
#include "common/conventions.h"
#include "options.h"

#include "mounts.h"

static int dir_ismounted(int *isfound_out, char *dir) {
// assume strlen(dir)!=0
int fd=-1;
char ch;
if (0>(fd=open("/proc/mounts",O_RDONLY))) GOTOERROR;
while (1) {
	char *match;
	int r;
	r=read(fd,&ch,1);
	if (r<=0) {
		if (!r) break;
		GOTOERROR;
	}
	while (1) {
		if (ch==' ') break;
		if (1!=read(fd,&ch,1)) GOTOERROR;
	}
	match=dir;
	while (1) {
		if (1!=read(fd,&ch,1)) GOTOERROR;
		if (ch!=*match) break;
		match++;
		if (!*match) {
			*isfound_out=1;
			close(fd);
			return 0;
		}
	}
	while (1) {
		if (1!=read(fd,&ch,1)) GOTOERROR;
		if (ch=='\n') break;
	}
}
close(fd);
*isfound_out=0;
return 0;
error:
	ifclose(fd);
	return -1;
}


int umount_mounts(struct options *options) {
char *dir;

if (!(dir=options->mount)) return 0;
if (!*dir) return 0;
if (!options->istryunmount) return 0;
while (1) {
	pid_t pid;
	int ret;

	if (dir_ismounted(&ret,dir)) GOTOERROR;
	if (!ret) break;
	pid=fork();
	if (!pid) {
		(ignore)execl("/bin/umount","umount",dir,NULL);
		_exit(1);
	}
	if (pid<0) GOTOERROR;
	while (pid!=waitpid(pid,NULL,0)) sleep(1);
	sleep(1);
}

options->istryunmount=0;
if (options->iswrite) {
	(void)sync();
	(void)sync();
}
// without a sleep after /bin/umount, the kernel barfs on writing to an invalid socket after it sends a CMD_DISC
// this is super-lame but I can't figure out how else to avoid it
sleep(4);
return 0;
error:
	return -1;
}

int mount_mounts(struct options *options) {
if (!options->mount) return 0;
pid_t pid;

pid=fork();
if (!pid) {
	(ignore)execl("/bin/mount","mount",options->mount,NULL);
	_exit(1);
}
if (pid<0) GOTOERROR;
while (pid!=waitpid(pid,NULL,0)) sleep(1);
options->istryunmount=1;
return 0;
error:
	return -1;
}

int dev_ismounted_mounts(int *isfound_out, char *dev) {
// assume strlen(dev)!=0
int fd=-1;
char ch;
if (0>(fd=open("/proc/mounts",O_RDONLY))) GOTOERROR;
while (1) {
	char *match;
	match=dev;
	while (1) {
		if (1!=read(fd,&ch,1)) GOTOERROR;
		if (ch!=*match) break;
		match++;
		if (!*match) {
			*isfound_out=1;
			close(fd);
			return 0;
		}
	}
	while (1) {
		if (1!=read(fd,&ch,1)) GOTOERROR;
		if (ch=='\n') break;
	}
}
close(fd);
*isfound_out=0;
return 0;
error:
	ifclose(fd);
	return -1;
}
