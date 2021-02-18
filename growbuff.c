/*
 * growbuff.c - a simple buffer that can grow
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
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
// #define DEBUG
#include "common/conventions.h"
#include "growbuff.h"

int init_growbuff(struct growbuff *g, uint64_t initsize) {
if (!fetch_growbuff(g,initsize)) GOTOERROR;
return 0;
error:
	return -1;
}
void deinit_growbuff(struct growbuff *g) {
iffree(g->buff);
}

unsigned char *fetch_growbuff(struct growbuff *g, uint64_t size) {
unsigned char *temp;
if (size<=g->max) return g->buff;
size+=(1<<16);
temp=realloc(g->buff,size);
if (!temp) GOTOERROR;
g->buff=temp;
g->max=size;
return temp;
error:
	return NULL;
}
