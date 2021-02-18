/*
 * nbdclient.h
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

#define MAX_EXPORTNAME_NBDCLIENT	127
struct nbdclient {
	int isconnected:1;
	int isreadonly:1; // did server reply READ_ONLY
	int iserror:1;
	int isfua:1;
	int istrimcmd:1;
	int isflushcmd:1;
	int isno0s:1;
	int isdebug:1;
	int isnamechange:1;
	int isnametoolong:1;
	int fd;
	struct addrinfo *ai;
	char exportname[MAX_EXPORTNAME_NBDCLIENT+1];
	char canon[MAX_EXPORTNAME_NBDCLIENT+1];
	char badcanon[MAX_EXPORTNAME_NBDCLIENT+1];
	unsigned int canonlen;
	unsigned int timeout;
	uint64_t exportsize;
};

void clear_nbdclient(struct nbdclient *n);
int init_nbdclient(struct nbdclient *n, struct addrinfo *ai, char *exportname, int iswrite, int isdebug, unsigned int timeout);
void deinit_nbdclient(struct nbdclient *n);
int connect_nbdclient(struct nbdclient *n);
int shutdown_nbdclient(struct nbdclient *n);
int readoff_nbdclient(void *opts, unsigned char *dest, uint64_t offset, unsigned int count);
void reset_nbdclient(struct nbdclient *n);
int writeoff_nbdclient(void *opts, unsigned char *dest, uint64_t offset, unsigned int count, int isfua);
int trim_nbdclient(void *opts, uint64_t offset, unsigned int count);
int flush_nbdclient(void *opts);
void removetail_nbdclient(struct nbdclient *n, unsigned char *tail, unsigned int len);
