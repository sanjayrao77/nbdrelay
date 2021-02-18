/*
 * options.h
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

struct options {
	int isverbose:1;	
	int isverifycert:1;
	int isdebug:1;
	int isdisconnect:1;
	int isstdin:1;
	int iswrite:1;
	int isrebuild:1;
	int isremount:1;
	int istryunmount:1;
	uint64_t exportsize;
	unsigned int shorttimeout;
	unsigned int longtimeout;
	char *device;
	char *url;
	char *str_user,*str_group;
	char *mount;
	char *certfile;
	char *keyfile;
	uid_t user;
	gid_t group;
	struct {
		char *url;
	} tofree;
};
