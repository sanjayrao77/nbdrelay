/*
 * unionio.c - generic io to handle multiple types (tls,notls,file)
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
#include <inttypes.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <inttypes.h>
#include <errno.h>
#ifdef HAVETLS
#include <gnutls/gnutls.h>
#endif
// #define DEBUG
#include "common/conventions.h"
#include "fileio.h"
#include "nbdclient.h"
#ifdef HAVETLS
#include "nbdtlsclient.h"
#endif

#include "unionio.h"

#if 0
static unsigned int strtou(char *str) {
unsigned int ret=0;
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
#endif

void deinit_unionio(struct unionio *u) {
switch (u->type) {
	case FILEIO_TYPE_UNIONIO:
		deinit_fileio(&u->fileio);
		break;
	case NBDCLIENT_TYPE_UNIONIO:
		deinit_nbdclient(&u->nbdclient);
		break;
#ifdef HAVETLS
	case NBDTLSCLIENT_TYPE_UNIONIO:
		deinit_nbdtlsclient(&u->nbdtlsclient);
		break;
#endif
}
if (u->tofree.ai) {
	(void)freeaddrinfo(u->tofree.ai);
}
}


SICLEARFUNC(addrinfo);
#define MAX_HOSTNAME	63
static int getsockaddr(struct addrinfo **ai_out, char *hostname, char *end_hostname, unsigned short defport) {
char buffer[MAX_HOSTNAME+1];
char portstr[6];
char *port;
unsigned short portnum=defport;
int l;
struct addrinfo *res=NULL,hints;

clear_addrinfo(&hints);
hints.ai_family=AF_UNSPEC;
hints.ai_socktype=SOCK_STREAM;
hints.ai_protocol=IPPROTO_TCP;

l=(int)(end_hostname-hostname);
if (l>MAX_HOSTNAME) GOTOERROR;
memcpy(buffer,hostname,l);
buffer[l]='\0';
port=strrchr(buffer,':');
if (port) {
	*port='\0';
	portnum=atoi(port+1);
}
sprintf(portstr,"%u",portnum);

// fprintf(stderr,"getaddrinfo, node:%s service:%s\n",buffer,portstr);
if (getaddrinfo(buffer,portstr,&hints,&res)) {
	syslog(LOG_ERR,"getaddrinfo returned %s",strerror(errno));
	GOTOERROR;
}
#if 0
{
	struct addrinfo *p;
	p=res;
	while (p) {
		fprintf(stderr,"addrinfo, flags:%d family:%d type:%d protocol:%d addrlen:%d name:%s\n",
				res->ai_flags,res->ai_family,res->ai_socktype,res->ai_protocol,res->ai_addrlen,res->ai_canonname);
		p=p->ai_next;
	}
}
#endif
*ai_out=res;
return 0;
error:
	if (res) (void)freeaddrinfo(res);
	return -1;
}

static inline char *strchror0(char *str, char ch) {
while (1) {
	if ((!*str) || (*str==ch)) return str;
	str++;
}
}

int init_unionio(struct unionio *u, int iswrite, int isdebug, char *url, unsigned int timeout,
		char *certfile, char *keyfile, int isverifycert) {

u->iswrite=iswrite;

if (!strncmp(url,"nbd://",6)) { // nbd://192.168.1.7:10809/example
	char *hostname,*export;
	u->type=NBDCLIENT_TYPE_UNIONIO;
	clear_nbdclient(&u->nbdclient);
	hostname=url+6;
	export=strchror0(hostname,'/');
	if (getsockaddr(&u->tofree.ai,hostname,export,10809)) GOTOERROR;
	export+=1;
	if (init_nbdclient(&u->nbdclient,u->tofree.ai,export,iswrite,isdebug,timeout)) GOTOERROR;
	u->readoff=readoff_nbdclient;
	u->writeoff=writeoff_nbdclient;
	u->trim=trim_nbdclient;
	u->flush=flush_nbdclient;
	u->offopt=&u->nbdclient;
#ifdef HAVETLS
} else if (!strncmp(url,"nbdtls://",9)) { // nbdtls://192.168.1.7:10809/example
	char *hostname,*export;
	u->type=NBDTLSCLIENT_TYPE_UNIONIO;
	clear_nbdtlsclient(&u->nbdtlsclient);
	hostname=url+9;
	export=strchror0(hostname,'/');
	if (getsockaddr(&u->tofree.ai,hostname,export,10809)) GOTOERROR;
	export+=1;
	if (init_nbdtlsclient(&u->nbdtlsclient,u->tofree.ai,export,iswrite,isdebug,timeout,certfile,keyfile,isverifycert)) GOTOERROR;
	u->readoff=readoff_nbdtlsclient;
	u->writeoff=writeoff_nbdtlsclient;
	u->trim=trim_nbdtlsclient;
	u->flush=flush_nbdtlsclient;
	u->offopt=&u->nbdtlsclient;
#endif
} else if (!strncmp(url,"file://",7)) {
	u->type=FILEIO_TYPE_UNIONIO;
	clear_fileio(&u->fileio);
	if (init_fileio(&u->fileio,url+7,iswrite)) GOTOERROR;
	u->readoff=readoff_fileio;
	u->writeoff=writeoff_fileio;
	u->trim=trim_fileio;
	u->flush=flush_fileio;
	u->offopt=&u->fileio;
} else GOTOERROR;

return 0;
error:
	return -1;
}

CLEARFUNC(unionio);
#if 0
// this probably works -- it might be useful for migration
int reinit_unionio(struct unionio *u, int isdebug, char *url, unsigned int timeout, char *certfile, char *keyfile, int isverifycert) {
int iswrite;
iswrite=u->iswrite;
(void)deinit_unionio(u);
clear_unionio(u);
return init_unionio(u,iswrite,isdebug,url,timeout,certfile,keyfile,isverifycert);
}
#endif

int connect_unionio(struct unionio *u) {
int iserror=0;

switch (u->type) {
	case FILEIO_TYPE_UNIONIO: u->size=u->fileio.size; break;
	case NBDCLIENT_TYPE_UNIONIO:
		if (connect_nbdclient(&u->nbdclient)) return -1;
		u->size=u->nbdclient.exportsize;
		if (u->nbdclient.iserror) {
			u->iserror=u->nbdclient.iserror;
			u->isnamechange=u->nbdclient.isnamechange;
			u->isnametoolong=u->nbdclient.isnametoolong;
			u->badcanon=u->nbdclient.badcanon;
		}
		break;
#ifdef HAVETLS
	case NBDTLSCLIENT_TYPE_UNIONIO:
		if (connect_nbdtlsclient(&u->nbdtlsclient)) return -1;
		u->size=u->nbdtlsclient.exportsize;
		if (u->nbdtlsclient.iserror) {
			u->iserror=u->nbdtlsclient.iserror;
			u->isnamechange=u->nbdtlsclient.isnamechange;
			u->isnametoolong=u->nbdtlsclient.isnametoolong;
			u->badcanon=u->nbdtlsclient.badcanon;
		}
		break;
#endif
}
if (iserror) return -1;
u->isconnected=1;
u->iserror=0;
if ((u->size!=u->orig_size) && u->orig_size) {
	u->isunrecoverable=1;
	u->isresize=1;
	return -1;
}
return 0;
}

int shutdown_unionio(struct unionio *u) {
u->isconnected=0;
switch (u->type) {
	case FILEIO_TYPE_UNIONIO: return shutdown_fileio(&u->fileio);
	case NBDCLIENT_TYPE_UNIONIO: return shutdown_nbdclient(&u->nbdclient);
#ifdef HAVETLS
	case NBDTLSCLIENT_TYPE_UNIONIO: return shutdown_nbdtlsclient(&u->nbdtlsclient);
#endif
}
return 0;
}

void reset_unionio(struct unionio *u) {
u->isconnected=0;
switch (u->type) {
	case FILEIO_TYPE_UNIONIO: break;
	case NBDCLIENT_TYPE_UNIONIO:
		u->iserror=u->nbdclient.iserror;
		(void)reset_nbdclient(&u->nbdclient);
		break;
#ifdef HAVETLS
	case NBDTLSCLIENT_TYPE_UNIONIO:
		u->iserror=u->nbdtlsclient.iserror;
		(void)reset_nbdtlsclient(&u->nbdtlsclient);
		break;
#endif
}
}

int readoff_unionio(struct unionio *u, unsigned char *dest, uint64_t offset, unsigned int count) {
if (!u->isconnected) {
	if (connect_unionio(u)) return -1;
}
if (u->readoff(u->offopt,dest,offset,count)) {;
	(void)reset_unionio(u);
	return -1;
}
return 0;
}

int isreadonly_unionio(struct unionio *u) {
// this should only be called if (u->isconnected) 
switch (u->type) {
	case FILEIO_TYPE_UNIONIO: return u->fileio.isreadonly;
	case NBDCLIENT_TYPE_UNIONIO: return u->nbdclient.isreadonly;
#ifdef HAVETLS
	case NBDTLSCLIENT_TYPE_UNIONIO: return u->nbdtlsclient.isreadonly;
#endif
}
return 1;
}

int writeoff_unionio(struct unionio *u, unsigned char *dest, uint64_t offset, unsigned int count, int isfua) {
if (!u->isconnected) {
	if (connect_unionio(u)) return -1;
}
if (u->writeoff(u->offopt,dest,offset,count,isfua)) {;
	if (isreadonly_unionio(u)) u->isroviolation = u->isunrecoverable = 1;
	(void)reset_unionio(u);
	return -1;
}
return 0;
}

int flush_unionio(struct unionio *u) {
if (!u->isconnected) {
	if (connect_unionio(u)) return -1;
}
if (u->flush(u->offopt)) {
	(void)reset_unionio(u);
	return -1;
}
return 0;
}

int trim_unionio(struct unionio *u, uint64_t offset, unsigned int count) {
if (!u->isconnected) {
	if (connect_unionio(u)) return -1;
}
if (u->trim(u->offopt,offset,count)) {;
	(void)reset_unionio(u);
	return -1;
}
return 0;
}

void removetail_unionio(struct unionio *u, unsigned char *tail, unsigned int len) {
switch (u->type) {
	case NBDCLIENT_TYPE_UNIONIO: removetail_nbdclient(&u->nbdclient,tail,len); break;
#ifdef HAVETLS
	case NBDTLSCLIENT_TYPE_UNIONIO: removetail_nbdtlsclient(&u->nbdtlsclient,tail,len); break;
#endif
}
}
