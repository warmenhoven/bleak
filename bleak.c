/*
 * bleak - leak detector
 * Copyright (C) 2003-2005  Eric Warmenhoven
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

#define _GNU_SOURCE

#include <bfd.h>
#include <dlfcn.h>
#include <execinfo.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

pthread_mutex_t lock = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
static int check_leaks = 0;

struct mem {
	void *addr;
	size_t size;
	void **bt;
	int btcount;
	int leaked;
	struct mem *prev;
	struct mem *next;
};

#define HASH_SIZE 100
static struct mem *hash[HASH_SIZE];

static void *(*libc_malloc)(size_t);
static void *(*libc_calloc)(size_t, size_t);
static void *(*libc_realloc)(void *, size_t);
static void (*libc_free)(void *);

static int total_size = 0;
static int high_water = 0;

#define MAX_BT 50
static int print_bt = 0;
extern void print_leaks(void);

#define HASH(addr) (((unsigned int)(addr) / (sizeof (void *))) % HASH_SIZE)

static void
set_check_leaks(int x)
{
	fprintf(stderr, "bleak: pid %d got signal %d\n", getpid(), x);
	check_leaks = 1;
}

static int
bleak_init()
{
	static int init = 0;
	int sig = SIGPWR;
	char *p;

	if (check_leaks) {
		check_leaks = 0;
		print_leaks();
	}

	if (init > 0)
		return (1);
	if (init < 0)
		return (0);

	/*
	 * dlsym may call malloc, which becomes recursive:
	 *
	 * malloc -> bleak_init -> dlsym -> malloc -> ...
	 *
	 * so we set init to -1, which causes bleak_init to return 0, which
	 * causes malloc to return NULL.
	 */
	init = -1;

	memset(hash, 0, sizeof (hash));

	libc_malloc = dlsym(RTLD_NEXT, "__libc_malloc");
	libc_calloc = dlsym(RTLD_NEXT, "__libc_calloc");
	libc_realloc = dlsym(RTLD_NEXT, "__libc_realloc");
	libc_free = dlsym(RTLD_NEXT, "__libc_free");

	if (getenv("BLEAK_ATEXIT")) {
		atexit(print_leaks);
	}
	if ((p = getenv("BLEAK_SIG")) != NULL) {
		int a = atoi(p);
		if (a != 0) {
			sig = a;
		}
	}
	signal(sig, set_check_leaks);
	fprintf(stderr, "bleak: pid %d signal %d\n", getpid(), sig);

	init = 1;

	return (1);
}

static inline void
hash_add(struct mem *m)
{
	struct mem *l;
	int i = 1;

	l = hash[HASH(m->addr)];
	if (!l) {
		hash[HASH(m->addr)] = m;
		m->prev = NULL;
	} else {
		while (l->next) {
			l = l->next;
			i++;
		}
		i++;
		l->next = m;
		m->prev = l;
	}
}

static inline struct mem *
hash_find(void *ptr)
{
	struct mem *m = hash[HASH(ptr)];
	while (m) {
		if (m->addr == ptr)
			return (m);
		m = m->next;
	}

	return (NULL);
}

static inline void
hash_remove(struct mem *m)
{
	if (m->prev)
		m->prev->next = m->next;
	else
		hash[HASH(m->addr)] = m->next;
	if (m->next)
		m->next->prev = m->prev;
}

void *
malloc(size_t size)
{
	void *addr;
	struct mem *m;

	if (print_bt)
		return (libc_malloc(size));

	if (size == 0)
		return (NULL);

	pthread_mutex_lock(&lock);

	if (!bleak_init()) {
		pthread_mutex_unlock(&lock);
		return (NULL);
	}

	addr = libc_malloc(size);
	if (!addr) {
		pthread_mutex_unlock(&lock);
		return (NULL);
	}

	total_size += size;
	if (total_size > high_water)
		high_water = total_size;

	m = libc_malloc(sizeof (struct mem));
	m->addr = addr;
	m->size = size;
	m->bt = libc_malloc(sizeof (void *) * MAX_BT);
	m->btcount = backtrace(m->bt, MAX_BT);
	if (m->btcount != MAX_BT)
		m->bt = libc_realloc(m->bt, sizeof (void *) * m->btcount);
	m->next = NULL;

	hash_add(m);

	pthread_mutex_unlock(&lock);

	return (addr);
}

void *
calloc(size_t nmemb, size_t size)
{
	void *addr;
	struct mem *m;

	if (print_bt)
		return (libc_calloc(nmemb, size));

	if (nmemb == 0 && size == 0)
		return (NULL);

	pthread_mutex_lock(&lock);

	if (!bleak_init()) {
		pthread_mutex_unlock(&lock);
		return (NULL);
	}

	addr = libc_calloc(nmemb, size);
	if (!addr) {
		pthread_mutex_unlock(&lock);
		return (NULL);
	}

	total_size += nmemb * size;
	if (total_size > high_water)
		high_water = total_size;

	m = libc_malloc(sizeof (struct mem));
	m->addr = addr;
	m->size = size * nmemb;
	m->bt = libc_malloc(sizeof (void *) * MAX_BT);
	m->btcount = backtrace(m->bt, MAX_BT);
	if (m->btcount != MAX_BT)
		m->bt = libc_realloc(m->bt, sizeof (void *) * m->btcount);
	m->next = NULL;

	hash_add(m);

	pthread_mutex_unlock(&lock);

	return (addr);
}

void
free(void *ptr)
{
	struct mem *m;

	if (print_bt) {
		libc_free(ptr);
		return;
	}

	if (ptr == NULL)
		return;

	pthread_mutex_lock(&lock);

	if (!bleak_init()) {
		pthread_mutex_unlock(&lock);
		return;
	}

	if (!(m = hash_find(ptr)))
		abort();

	total_size -= m->size;

	hash_remove(m);

	libc_free(ptr);
	libc_free(m->bt);
	libc_free(m);

	pthread_mutex_unlock(&lock);
}

void *
realloc(void *ptr, size_t size)
{
	void *addr;
	struct mem *m;

	if (print_bt)
		return (libc_realloc(ptr, size));

	if (ptr == NULL)
		return (malloc(size));
	if (size == 0) {
		free(ptr);
		return (NULL);
	}

	pthread_mutex_lock(&lock);

	if (!bleak_init()) {
		pthread_mutex_unlock(&lock);
		return (NULL);
	}

	if (!(m = hash_find(ptr)))
		abort();

	addr = libc_realloc(ptr, size);
	if (!addr) {
		pthread_mutex_unlock(&lock);
		return (NULL);
	}

	hash_remove(m);

	total_size -= m->size;
	libc_free(m->bt);

	total_size += size;
	if (total_size > high_water)
		high_water = total_size;

	m->addr = addr;
	m->size = size;
	m->bt = libc_malloc(sizeof (void *) * MAX_BT);
	m->btcount = backtrace(m->bt, MAX_BT);
	if (m->btcount != MAX_BT)
		m->bt = libc_realloc(m->bt, sizeof (void *) * m->btcount);
	m->next = NULL;

	hash_add(m);

	pthread_mutex_unlock(&lock);

	return (addr);
}

struct map {
	struct map *next;
	unsigned int start;
	unsigned int end;
	char file[256];
	bfd *abfd;
	asection *section;
	asymbol **syms;
};

static struct map *maps = NULL;

static int
fdgets(char *buf, int size, int fd)
{
	int i;
	for (i = 0; i < size - 1; i++) {
		int rc = read(fd, &buf[i], 1);
		if (rc < 0)
			return (rc);
		if (rc == 0)
			return (i);
		if (buf[i] == '\n') {
			buf[i + 1] = 0;
			return (i);
		}
	}

	buf[i] = 0;
	return (i);
}

static struct map *
find_map(unsigned int addr)
{
	struct map *m = maps;

	while (m) {
		if (addr >= m->start && addr < m->end)
			return (m);
		m = m->next;
	}

	return (NULL);
}

static void
make_map(unsigned int start, unsigned int end, char *file)
{
	struct map *l, *m;

	if (find_map(start))
		return;

	m = libc_calloc(1, sizeof (struct map));
	m->start = start;
	m->end = end;
	strcpy(m->file, file);

	if (maps) {
		l = maps;
		while (l->next)
			l = l->next;
		l->next = m;
	} else {
		maps = m;
	}
}

static int
read_bfd(struct map *m)
{
	long storage;

	if (!(m->abfd = bfd_openr(m->file, NULL)))
		return (0);
	if (!bfd_check_format(m->abfd, bfd_object)) {
		bfd_close(m->abfd);
		m->abfd = NULL;
		return (0);
	}
	if (!(bfd_get_file_flags(m->abfd) & HAS_SYMS)) {
		bfd_close(m->abfd);
		m->abfd = NULL;
		return (0);
	}
	for (m->section = m->abfd->sections; m->section;
	     m->section = m->section->next)
		if (strcmp(m->section->name, ".text") == 0)
			break;
	if (!m->section) {
		bfd_close(m->abfd);
		m->abfd = NULL;
		return (0);
	}
	if ((storage = bfd_get_symtab_upper_bound(m->abfd)) <= 0) {
		bfd_close(m->abfd);
		m->section = NULL;
		m->abfd = NULL;
		return (0);
	}
	m->syms = libc_malloc(storage);
	if (bfd_canonicalize_symtab(m->abfd, m->syms) <= 0) {
		libc_free(m->syms);
		m->syms = NULL;
		m->section = NULL;
		bfd_close(m->abfd);
		m->abfd = NULL;
		return (0);
	}
	return (1);
}

static void
print_backtrace(FILE *outfile, struct mem *mem)
{
	int i;

	for (i = 0; i < mem->btcount; i++) {
		const char *file, *func;
		unsigned int line;
		unsigned int addr;
		struct map *map;

		addr = (unsigned int)mem->bt[i];

		map = find_map(addr);

		if (!map) {
			fprintf(outfile, "[0x%08x]\n", addr);
		} else if (!map->abfd && !read_bfd(map)) {
			fprintf(outfile, "[0x%08x] %s\n", addr, map->file);
		} else if (!bfd_find_nearest_line(map->abfd, map->section, map->syms,
										  addr - map->section->vma, &file,
										  &func, &line)) {
			fprintf(outfile, "[0x%08x] %s\n", addr, map->file);
		} else if (file) {
			fprintf(outfile, "[0x%08x] %s(): %s:%u\n", addr, func, file, line);
		} else {
			fprintf(outfile, "[0x%08x] %s()\n", addr, func);
		}
	}
}

void
print_leaks()
{
	FILE *file;
	int fd;
	char buf[1024];
	struct mem *mem;
	int i;
	int numallocs = 0;
	int leaks = 0, leaktot = 0;

	struct timeval start_tv;
	struct timeval done_tv;
	int worked;
	int worked_ms;

	fprintf(stderr, "bleak: pid %d checking leaks\n", getpid());

	if ((fd = open("/proc/self/maps", O_RDONLY)) < 0) {
		fprintf(stderr, "bleak: pid %d open failed!\n", getpid());
		return;
	}

	print_bt = 1;

	gettimeofday(&start_tv, NULL);

	for (i = 0; i < HASH_SIZE; i++) {
		mem = hash[i];
		while (mem) {
			mem->leaked = 1;
			leaks++;
			leaktot += mem->size;
			mem = mem->next;
		}
	}
	numallocs = leaks;

	while (leaks && fdgets(buf, 1024, fd) > 0) {
		unsigned int start, end;
		char file[256], perms[16];
		void **ptr;
		struct map *map;
		sscanf(buf, "%x-%x %15s %*x %*u:%*u %*u %255s",
		       &start, &end, perms, file);
		if (perms[0] == '-' || perms[1] == '-')
			continue;
		make_map(start, end, file);
		for (ptr = (void **)start; leaks && ptr < (void **)end; ptr++) {
			if (!(mem = hash_find(*ptr)))
				continue;
			if (ptr == &mem->addr)
				continue;
			if (!mem->leaked)
				continue;
			if ((map = find_map((unsigned int)*ptr)) != NULL &&
			    (ptr == (void *)&map->start || ptr == (void *)&map->end))
				continue;
			mem->leaked = 0;
			leaks--;
			leaktot -= mem->size;
		}
	}
	close(fd);

	gettimeofday(&done_tv, NULL);

	worked = done_tv.tv_sec - start_tv.tv_sec;
	if (done_tv.tv_usec >= start_tv.tv_usec) {
		worked_ms = (done_tv.tv_usec - start_tv.tv_usec) / 1000;
	} else {
		worked_ms = (done_tv.tv_usec / 1000) +
			(1000 - (start_tv.tv_usec / 1000));
	    worked--;
	}

	fprintf(stderr, "bleak: pid %d leak check time %d.%03d seconds\n",
			getpid(), worked, worked_ms);

	i = readlink("/proc/self/exe", buf, 1024);
	buf[i] = 0;
	fprintf(stderr, "\n\n%s:\n", buf);
	fprintf(stderr, "%d bytes allocated in %d allocs, %d bytes average\n",
		total_size, numallocs, total_size / numallocs);
	fprintf(stderr, "%d max bytes allocated\n", high_water);
	if (!leaks) {
		fprintf(stderr, "No Leaks!\n\n");
		print_bt = 0;
		return;
	}

	fprintf(stderr, "\n%d leaks totalling %d bytes:\n", leaks, leaktot);
	snprintf(buf, 1024, "%d.leaks", getpid());
	file = fopen(buf, "w");
	if (file == NULL) {
		file = stderr;
	} else {
		fprintf(stderr, "dumping leak backtraces to %s\n", buf);
	}
	for (i = 0; i < HASH_SIZE; i++) {
		mem = hash[i];
		while (mem) {
			if (mem->leaked) {
				fprintf(file, " %p %d bytes\n", mem->addr, mem->size);
				print_backtrace(file, mem);
				leaks++;
				leaktot += mem->size;
			}
			mem = mem->next;
		}
	}
	if (file != stderr)
		fclose(file);
	print_bt = 0;
}
