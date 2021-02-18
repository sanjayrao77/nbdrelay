/*
 * fileio.c - hand local i/o
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
#define _LARGEFILE64_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <endian.h>
#include <zlib.h>
// #define DEBUG
#include "common/conventions.h"
#include "misc.h"

#include "fileio.h"

void clear_fileio(struct fileio *f) {
static struct fileio blank={.fd=-1};
*f=blank;
}

int init_fileio(struct fileio *f, char *filename, int iswrite) {
off_t o;
int flags;
flags=(iswrite)?O_RDWR:O_RDONLY;
if (-1==(f->fd=open(filename,flags))) GOTOERROR;
if (-1==(o=lseek64(f->fd,0,SEEK_END))) GOTOERROR;
f->size=(uint64_t)o;
f->isreadonly=((!iswrite));
return 0;
error:
	return -1;
}

static inline int readoff(int fd, unsigned char *dest, uint64_t offset, unsigned int count) {
if (0>lseek64(fd,offset,SEEK_SET)) GOTOERROR;
return readn(fd,dest,count);
error:
	return -1;
}

int readoff_fileio(void *opts, unsigned char *dest, uint64_t offset, unsigned int count) {
struct fileio *f=(struct fileio *)opts;
return readoff(f->fd,dest,offset,count);
}

static inline int writeoff(int fd, unsigned char *dest, uint64_t offset, unsigned int count) {
if (0>lseek64(fd,offset,SEEK_SET)) GOTOERROR;
return writen(fd,dest,count);
error:
	return -1;
}

int writeoff_fileio(void *opts, unsigned char *dest, uint64_t offset, unsigned int count, int isfua) {
struct fileio *f=(struct fileio *)opts;
int r;
r=writeoff(f->fd,dest,offset,count);
if (isfua) {
	if (!r) r=fsync(f->fd);
}
return r;
}

void deinit_fileio(struct fileio *f) {
ifclose(f->fd);
}

int shutdown_fileio(struct fileio *f) {
int ret;
if (f->fd<0) return 0;
ret=close(f->fd);
f->fd=-1;
return ret;
}

int flush_fileio(void *opts) {
struct fileio *f=(struct fileio *)opts;
return fsync(f->fd);
}

int trim_fileio(void *opts, uint64_t offset, unsigned int count) {
// pointless
return 0;
}
