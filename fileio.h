/*
 * fileio.h
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

struct fileio {
	int isreadonly:1;
	int fd;
	uint64_t size;
};

void clear_fileio(struct fileio *f);
int init_fileio(struct fileio *f, char *filename, int iswrite);
void deinit_fileio(struct fileio *f);
int shutdown_fileio(struct fileio *f);
int readoff_fileio(void *opts, unsigned char *dest, uint64_t offset, unsigned int count);
int writeoff_fileio(void *opts, unsigned char *dest, uint64_t offset, unsigned int count, int isfua);
int flush_fileio(void *opts);
int trim_fileio(void *opts, uint64_t offset, unsigned int count);
