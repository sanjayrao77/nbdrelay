/*
 * misc.c - various utility functions
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
#define _FILE_OFFSET_BITS 64
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>
#include <syslog.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include "common/conventions.h"

#include "misc.h"

int ismappedipv4_misc(unsigned char *ipv6) {
unsigned char mapprefix[12]={0,0,0,0, 0,0,0,0, 0,0,255,255};
if (!memcmp(ipv6,mapprefix,12)) return 1;
return 0;
}


int timeout_writen(int fd, unsigned char *buff, unsigned int n, time_t maxtime) {
fd_set wset;
if (n) while (1) {
	struct timeval tv;
	time_t t;
	int k;
	FD_ZERO(&wset);
	FD_SET(fd,&wset);
	t=time(NULL);
	if (t>=maxtime) {
#ifdef DEBUG2
		fprintf(stderr,"Timeout sending to server.\n");
#endif
		GOTOERROR;
	}
	tv.tv_sec=maxtime-t;
	tv.tv_usec=0;
	switch (select(fd+1,NULL,&wset,NULL,&tv)) { case 0: continue; case -1: if (errno==EINTR) continue; GOTOERROR; }
	k=write(fd,buff,n);
	if (k<=0) {
		if ((k==-1)&&(errno==EINTR)) continue;
		GOTOERROR;
	}
	n-=k;
	if (!n) break;
	buff+=k;
}
return 0;
error:
	return -1;
}

unsigned char zero128_misc[128];

int timeout_write0s(int fd, unsigned int n, time_t maxtime) {
fd_set wset;
if (n) while (1) {
	struct timeval tv;
	time_t t;
	int k;
	FD_ZERO(&wset);
	FD_SET(fd,&wset);
	t=time(NULL);
	if (t>=maxtime) {
#ifdef DEBUG2
		fprintf(stderr,"Timeout sending to server.\n");
#endif
		GOTOERROR;
	}
	tv.tv_sec=maxtime-t;
	tv.tv_usec=0;
	switch (select(fd+1,NULL,&wset,NULL,&tv)) { case 0: continue; case -1: if (errno==EINTR) continue; GOTOERROR; }
	k=write(fd,zero128_misc,_BADMIN(n,128));
	if (k<=0) {
		if ((k==-1)&&(errno==EINTR)) continue;
		GOTOERROR;
	}
	n-=k;
	if (!n) break;
}
return 0;
error:
	return -1;
}
int timeout_readn(int fd, unsigned char *buff, unsigned int n, time_t maxtime) {
fd_set rset;
if (n) while (1) {
	struct timeval tv;
	time_t t;
	int k;
	FD_ZERO(&rset);
	FD_SET(fd,&rset);
	t=time(NULL);
	if (t>=maxtime) {
		return -2;
	}
	tv.tv_sec=maxtime-t;
	tv.tv_usec=0;
	switch (select(fd+1,&rset,NULL,NULL,&tv)) { case 0: continue; case -1: if (errno==EINTR) continue; GOTOERROR; }
	k=read(fd,buff,n);
	if (k<=0) {
//		if ((k==-1)&&(errno==EINTR)) continue;
		GOTOERROR;
	}
	n-=k;
	if (!n) break;
	buff+=k;
}
return 0;
error:
	return -1;
}
static inline void getdoublecolon(unsigned int *dcleft_out, unsigned int *dclen_out, unsigned char *ipv6) {
unsigned int ui;
unsigned char *ptr;
unsigned int highest=2;
unsigned int highestleft=17;

ui=0;
ptr=ipv6;
while (1) {
	unsigned char *run;
	unsigned int uj;
	unsigned int runlen=0;
	run=ptr;
	uj=ui;
	while (1) {
		if (run[0]) break;
		if (run[1]) break;
		run+=2;
		runlen+=2;
		uj+=2;
		if (uj==16) break;
	}
	if (runlen>highest) { highest=runlen; highestleft=16-ui; }
	ui+=2;
	if (ui==16) break;
	ptr+=2;
}
*dcleft_out=highestleft;
*dclen_out=highest;
}

int printipv6_misc(FILE *fout, unsigned char ipv6[16]) {
char dest[40];
(void)iptostr_misc(dest,ipv6);
if (EOF!=fputs(dest,fout)) return -1;
return 0;
}

void iptostr_misc(char *dest40, unsigned char ipv6[16]) {
char hexchars[]="0123456789abcdef";
unsigned int dcleft,dclen;
unsigned char *cur;
unsigned int left;

if (ismappedipv4_misc(ipv6)) {
	unsigned char *ipv4;
	ipv4=ipv6+12;
	snprintf(dest40,40,"%u.%u.%u.%u", ipv4[0], ipv4[1], ipv4[2], ipv4[3]);
	return;
}
(void)getdoublecolon(&dcleft,&dclen,ipv6);

cur=ipv6;
left=16;
if (dcleft==16) { *dest40=':'; dest40+=1; }
while (1) {
	if (dcleft==left) {
		*dest40=':';
		dest40+=1;
		left-=dclen;
		if (!left) break;
		cur+=dclen;
	}
	if (cur[0]&0xf0) {
		*dest40=hexchars[*cur/16]; dest40+=1;
		*dest40=hexchars[*cur%16]; dest40+=1;
		cur++;
		*dest40=hexchars[*cur/16]; dest40+=1;
		*dest40=hexchars[*cur%16]; dest40+=1;
		cur++;
	} else if (cur[0]&0xf) {
		*dest40=hexchars[*cur%16]; dest40+=1;
		cur++;
		*dest40=hexchars[*cur/16]; dest40+=1;
		*dest40=hexchars[*cur%16]; dest40+=1;
		cur++;
	} else if (cur[1]&0xf0) {
		cur++;
		*dest40=hexchars[*cur/16]; dest40+=1;
		*dest40=hexchars[*cur%16]; dest40+=1;
		cur++;
	} else {
		cur++;
		*dest40=hexchars[*cur%16]; dest40+=1;
		cur++;
	}
	left-=2;
	if (!left) break;
	*dest40=':'; dest40+=1;
}
*dest40='\0';
}

static inline unsigned int bytestocolonorend(char *str) {
unsigned int ui=0;
while (1) {
	switch (*str) {
		case '/':
		case ':': case 0: return ui;
	}
	ui++;
	str++;
}
}
static inline unsigned int hexval(unsigned int a, unsigned int b) {
if (a&64) a=((a&31)+9)<<4;
else a=(a&15)<<4;
if (b&64) b=(b&31)+9;
else b=b&15;
return a|b;
}

int isipv6_misc(uint64_t *high_ipv6_out, uint64_t *low_ipv6_out, uint64_t *high_netmask_out, uint64_t *low_netmask_out, char *src) {
#ifdef DEBUG
char hex[33];
#else
char hex[32];
#endif
unsigned int coloncount=0;
int ispastdoublecolon=0;
char *cur;
uint64_t high_ipv6,low_ipv6,high_netmask,low_netmask;

#ifdef DEBUG
hex[32]=0;
#endif
for (cur=src;*cur;cur++) if (*cur==':') coloncount+=1;
if (coloncount>7) return 0;
if (coloncount<2) return 0;
cur=hex;
if (*src==':') {
	src+=1;
	if (*src!=':') return 0;
	memset(cur,'0',4);
	cur+=4;
}
while (1) {
	unsigned int len;
	len=bytestocolonorend(src);
	switch (len) {
		case 0:
				if (*src!=':') { if (cur!=hex+32) return 0; goto doublebreak; }
				if (ispastdoublecolon) return 0;
				ispastdoublecolon=1;
				{
					int ellipsis;
					ellipsis=8-coloncount;
					if (!src[1]) ellipsis++;
					do { memcpy(cur,"0000",4); cur+=4; ellipsis--; } while (ellipsis);
				}
				break;
		case 1: *cur='0'; cur++; *cur='0'; cur++; *cur='0'; cur++; 
						*cur=*src; cur++; src++;
						break;
		case 2: *cur='0'; cur++; *cur='0'; cur++;
						*cur=*src; cur++; src++; *cur=*src; cur++; src++;
						break;
		case 3: *cur='0'; cur++;
						*cur=*src; cur++; src++; *cur=*src; cur++; src++; *cur=*src; cur++; src++;
						break;
		case 4: *cur=*src; cur++; src++; *cur=*src; cur++; src++; *cur=*src; cur++; src++; *cur=*src; cur++; src++;
						break;
		default: return 0;
	}
	src++; // ':'
}
doublebreak:
#if 0
fprintf(stderr,"%s:%d %s hex:\"%s\"\n",__FILE__,__LINE__,__FUNCTION__,hex);
#endif
{
	unsigned int ui;
	cur=hex;
	high_ipv6=0;
	for (ui=0;ui<8;ui++) {
		high_ipv6<<=8;
		high_ipv6|=hexval(cur[0],cur[1]);
		cur+=2;
	}
	low_ipv6=0;
	for (ui=0;ui<8;ui++) {
		low_ipv6<<=8;
		low_ipv6|=hexval(cur[0],cur[1]);
		cur+=2;
	}
}
if (*src=='/') {
	unsigned int bit;
	bit=atoi(src+1);
	if (bit>128) return 0;
	if (!bit) { // don't allow everything just for a typo; require a defined ::0
		if (high_ipv6) return 0;
		if (low_ipv6) return 0;
	}
	if (bit<=64) {
		high_netmask=~0;
		high_netmask<<=(64-bit);
		low_netmask=0;

		high_ipv6&=high_netmask;
		low_ipv6=0;
	} else {
		high_netmask=~0;
		low_netmask=~0;
		low_netmask<<=(128-bit);

		low_ipv6&=low_netmask;
	}
} else {
	high_netmask=~0;
	low_netmask=~0;
}
*high_ipv6_out=high_ipv6;
*low_ipv6_out=low_ipv6;
*high_netmask_out=high_netmask;
*low_netmask_out=low_netmask;
return 1;
}

int isipv4_misc(unsigned int *ui_ipv4_out, unsigned int *netmask_out, char *src) {
unsigned int ip32=0,ui=0;
unsigned int netmask=32;
int dotcount=0;
while (1) {
	switch (*src) {
		case '0': ui=ui*10+0; break; case '1': ui=ui*10+1; break; case '2': ui=ui*10+2; break;
		case '3': ui=ui*10+3; break; case '4': ui=ui*10+4; break; case '5': ui=ui*10+5; break;
		case '6': ui=ui*10+6; break; case '7': ui=ui*10+7; break; case '8': ui=ui*10+8; break;
		case '9': ui=ui*10+9; break;
		case '/':
			switch (dotcount) {
				case 0: ip32=ui; break;
				case 3: if (ui&~255) return 0; ip32=(ip32<<8)|ui; break;
				default: return 0;
			}
			netmask=atoi(src+1);
			if (!netmask) { // If we're going to allow everything, require a definite 0.0.0.0
				if (ui) return 0;
			}
			if (netmask>32) return 0;
			netmask=(~0)<<(32-netmask);
			ip32&=netmask;
			*netmask_out=netmask;
			*ui_ipv4_out=ip32;
			return 1;
		case 0:
			switch (dotcount) {
				case 0: ip32=ui; break;
				case 3: if (ui&~255) return 0; ip32=(ip32<<8)|ui; break;
				default: return 0;
			}
			*netmask_out=~0;
			*ui_ipv4_out=ip32;
			return 1;
		case '.':
			if (ui&~255) return 0;
			dotcount++;
			ip32=(ip32<<8)|ui;
			ui=0;
			break;
		
	}
	src++;
}
}

#ifdef DEBUG
void hexdump_misc(void *ptr, unsigned int len, unsigned int line) {
unsigned int ui=0;
unsigned char *uc=(unsigned char *)ptr;
fprintf(stderr,"%s:%u Hex dump %u bytes\n",__FILE__,line,len);
while (len) {
	ui++;
	if (ui==32) { ui=0; fprintf(stderr,"\n"); }
	fprintf(stderr," %02x",*uc);
	len--;
	uc++;
}
fprintf(stderr,"\n");
}
#endif

int getsize2_blockdevice(uint64_t *size_out, int fd) {
if (0>ioctl(fd,BLKGETSIZE64,size_out)) GOTOERROR;
return 0;
error:
	return -1;
}
int getsize_blockdevice(uint64_t *size_out, char *filename) {
int fd;
if (0>(fd=open(filename,O_RDONLY))) GOTOERROR;
if (getsize2_blockdevice(size_out,fd)) GOTOERROR;
(ignore)close(fd);
return 0;
error:
	ignore_ifclose(fd);
	return -1;
}

int getuid_misc(uid_t *uid_out, char *user) {
struct passwd *p;
if (!*user) { *uid_out=0; return 0; }
if (!(p=getpwnam(user))) GOTOERROR;
*uid_out=p->pw_uid;
return 0;
error:
	return -1;
}

int getgid_misc(gid_t *gid_out, char *group) {
struct group *g;
if (!*group) { *gid_out=0; return 0; }
if (!(g=getgrnam(group))) GOTOERROR;
*gid_out=g->gr_gid;
return 0;
error:
	return -1;
}

uint64_t atou64(char *str) {
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

uint32_t atou32(char *str) {
uint32_t ret=0;
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

#if 0
int s_readn(int fd, unsigned char *buff, unsigned int n_in) {
unsigned int n=n_in;
while (1) {
	int k;
	k=read(fd,buff,n);
	if (k<=0) {
		if ((k==-1)&&(errno==EINTR)) {
			if (n==n_in) return 1;
			continue;
		}
		return -1;
	}
	n-=k;
	if (!n) break;
	buff+=k;
}
return 0;
}
#endif

int readn(int fd, unsigned char *buff, unsigned int n) {
while (1) {
	int k;
	k=read(fd,buff,n);
	if (k<=0) {
//		if ((k==-1)&&(errno==EINTR)) continue;
		return -1;
	}
	n-=k;
	if (!n) break;
	buff+=k;
}
return 0;
}

int writen(int fd, unsigned char *buff, unsigned int n) {
while (1) {
	int k;
	k=write(fd,buff,n);
	if (k<=0) {
//		if ((k==-1)&&(errno==EINTR)) continue;
		return -1;
	}
	n-=k;
	if (!n) break;
	buff+=k;
}
return 0;
}

int isdevice_misc(int *isthere_out, char *filename) {
uint64_t size;
int fd;
fd=open(filename,O_RDONLY);
if (fd<0) {
	switch (errno) {
		case ENOENT: case ENODEV: case ENXIO:
			*isthere_out=0;
			return 0;
	}
	GOTOERROR;
}
if (getsize2_blockdevice(&size,fd)) GOTOERROR;
(ignore)close(fd);
*isthere_out=(size)?1:0;
return 0;
error:
	ignore_ifclose(fd);
	return -1;
}
