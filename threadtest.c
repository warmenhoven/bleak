#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

extern void print_leaks();
static void *
malloc_loop(void *arg)
{
	int i;
	for (i = 1; i <= 20 ; i++) {
		if (arg)
			printf("spawned thread %d\n", i);
		else
			printf("main thread %d\n", i);
		malloc(i * 64);
		sleep(3);
	}

	if (arg)
		printf("spawned thread\n");
	else
		printf("main thread\n");
	print_leaks();
	return NULL;
}

int main()
{
	pthread_t thread;

	pthread_create(&thread, NULL, malloc_loop, (void *)1);

	malloc_loop(NULL);

	pthread_join(thread, NULL);

	return 0;
}
