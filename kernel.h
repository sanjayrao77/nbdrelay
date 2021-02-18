/*
 * kernel.h
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

#if 0
// this version doesn't require pthreads but it takes slightly more ram and uses another pid
struct tracking_kernel {
	pid_t pid;
};
int fork_kernel(struct tracking_kernel *tracking, int sock, uint64_t size, struct options *options);
#endif

#if 1
// this is the only part that uses pthreads
struct tracking_kernel {
	int isvalid:1;
	int isjoinable:1;
	pthread_t pthread;
	volatile sig_atomic_t isalive;
	struct {
		int sock;
		uint64_t size;
		struct options *options;
	} params;
};
int thread_kernel(struct tracking_kernel *tracking, int sock, uint64_t size, struct options *options);
#endif

void clear_tracking_kernel(struct tracking_kernel *tk);
int disconnect_kernel(struct options *options, int isclear);
void wait_kernel(struct tracking_kernel *tk);
