#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void *my_alloc()
{
	return malloc(4);
}

void *my_strdup()
{
	return strdup("lalala");
}

extern void print_leaks();

int main(int argc, char **argv)
{
	malloc(5);
	my_alloc();
	free(my_strdup());
	my_strdup();
	my_alloc();
	free(my_strdup());
	my_strdup();
	my_alloc();
	free(my_strdup());
	my_strdup();
	my_alloc();
	free(my_strdup());
	my_strdup();
	printf("printing leaks\n");
	print_leaks();
	if (argc > 1)
		while(1);
	return 0;
}
