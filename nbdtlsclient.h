/*
 * nbdtlsclient.h
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

#define MAX_EXPORTNAME_NBDTLSCLIENT	127
#define MAX_FILENAME_NBDTLSCLIENT	127
struct nbdtlsclient {
	int isconnected:1;
	int isreadonly:1;
	int iserror:1;
	int isfua:1;
	int istrimcmd:1;
	int isflushcmd:1;
	int isno0s:1;
	int isdebug:1;
	int isnamechange:1;
	int isnametoolong:1;

	int isglobalinit:1;
	int isx509alloc:1;
	int isx509set:1;
	int issessioninit:1;
	int isverifycert:1;
	int fd;
	struct addrinfo *ai;
	char exportname[MAX_EXPORTNAME_NBDTLSCLIENT+1];
	char canon[MAX_EXPORTNAME_NBDTLSCLIENT+1];
	char badcanon[MAX_EXPORTNAME_NBDTLSCLIENT+1];
	unsigned int canonlen;
	char cacertfile[MAX_FILENAME_NBDTLSCLIENT+1];
	char certfile[MAX_FILENAME_NBDTLSCLIENT+1];
	char keyfile[MAX_FILENAME_NBDTLSCLIENT+1];
	unsigned int timeout;
	uint64_t exportsize;
	gnutls_certificate_credentials_t x509_cred;
	gnutls_session_t	tlssession;
};

void clear_nbdtlsclient(struct nbdtlsclient *n);
int init_nbdtlsclient(struct nbdtlsclient *n, struct addrinfo *ai, char *exportname, int iswrite, int isdebug, unsigned int timeout,
		char *certfile, char *keyfile, int isverifycert);
void deinit_nbdtlsclient(struct nbdtlsclient *n);
int shutdown_nbdtlsclient(struct nbdtlsclient *n);
int readoff_nbdtlsclient(void *opts, unsigned char *dest, uint64_t offset, unsigned int count);
void reset_nbdtlsclient(struct nbdtlsclient *n);
int connect_nbdtlsclient(struct nbdtlsclient *n);
int writeoff_nbdtlsclient(void *opts, unsigned char *dest, uint64_t offset, unsigned int count, int isfua);
int trim_nbdtlsclient(void *opts, uint64_t offset, unsigned int count);
int flush_nbdtlsclient(void *opts);
void removetail_nbdtlsclient(struct nbdtlsclient *n, unsigned char *tail, unsigned int len);
