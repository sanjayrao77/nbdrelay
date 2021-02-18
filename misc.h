/*
 * misc.h
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

extern unsigned char zero128_misc[128];
 
int writen(int fd, unsigned char *buff, unsigned int n);
int readn(int fd, unsigned char *buff, unsigned int n);
int s_readn(int fd, unsigned char *buff, unsigned int n_in);
int timeout_writen(int fd, unsigned char *buff, unsigned int n, time_t maxtime);
int timeout_write0s(int fd, unsigned int n, time_t maxtime);
int timeout_readn(int fd, unsigned char *buff, unsigned int n, time_t maxtime);
void iptostr_misc(char *dest40, unsigned char ipv6[16]);
int printipv6_misc(FILE *fout, unsigned char ipv6[16]);
int isipv6_misc(uint64_t *high_ipv6_out, uint64_t *low_ipv6_out, uint64_t *high_netmask_out, uint64_t *low_netmask_out, char *src);
int isipv4_misc(unsigned int *be32_out, unsigned int *netmask_out, char *src);
int ismappedipv4_misc(unsigned char *ipv6);
void hexdump_misc(void *ptr, unsigned int len, unsigned int line);
int getsize_blockdevice(uint64_t *size_out, char *filename);
int getsize2_blockdevice(uint64_t *size_out, int fd);
int getuid_misc(uid_t *uid_out, char *user);
int getgid_misc(gid_t *gid_out, char *group);
uint64_t atou64(char *str);
uint32_t atou32(char *str);
int isdevice_misc(int *isthere_out, char *filename);
