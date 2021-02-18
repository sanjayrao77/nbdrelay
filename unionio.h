/*
 * unionio.h
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

#define FILEIO_TYPE_UNIONIO				1
#define NBDCLIENT_TYPE_UNIONIO		2
#ifdef HAVETLS
#define NBDTLSCLIENT_TYPE_UNIONIO	3
#endif

struct unionio {
	int isconnected:1;
	int isunrecoverable:1;
	int isroviolation:1;
	int isnamechange:1;
	int isnametoolong:1;
	int isresize:1;
	int iserror:1; // IO error, incompatible interface, or no service
	int iswrite:1;
	char *badcanon; // points into union
	uint64_t size;
	uint64_t orig_size;
	struct {
		struct addrinfo *ai;
	} tofree;
	int type;
	union {
		struct fileio fileio;
		struct nbdclient nbdclient;
#ifdef HAVETLS
		struct nbdtlsclient nbdtlsclient;
#endif
	};
	int (*readoff)(void *,unsigned char *,uint64_t,unsigned int);
	int (*writeoff)(void *,unsigned char *,uint64_t,unsigned int,int);
	int (*trim)(void *,uint64_t,unsigned int);
	int (*flush)(void *);
	void *offopt;
};

H_CLEARFUNC(unionio);
void deinit_unionio(struct unionio *u);
int init_unionio(struct unionio *u, int iswrite, int isdebug, char *url, unsigned int timeout,
		char *certfile, char *keyfile, int isverifycert);
int reinit_unionio(struct unionio *u, int isdebug, char *url, unsigned int timeout, char *certfile, char *keyfile, int isverifycert);
int connect_unionio(struct unionio *u);
int shutdown_unionio(struct unionio *u);
void reset_unionio(struct unionio *u);
int readoff_unionio(struct unionio *u, unsigned char *dest, uint64_t offset, unsigned int count);
int isreadonly_unionio(struct unionio *u);
int writeoff_unionio(struct unionio *u, unsigned char *dest, uint64_t offset, unsigned int count, int isfua);
int flush_unionio(struct unionio *u);
int trim_unionio(struct unionio *u, uint64_t offset, unsigned int count);
void removetail_unionio(struct unionio *u, unsigned char *tail, unsigned int len);
