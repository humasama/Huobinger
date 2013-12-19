#include <stdio.h>
#include <stdlib.h>
#include "fire_common.h"

char *FIRE_PRINT_MSG[PRINT_LEVELS] = {
		" stat",
		"fatal",
		"error",
		" warn",
		" info",
		"debug"
};

static void show_stackframe() {
  void *trace[32];
  char **messages = (char **)NULL;
  int i, trace_size = 0;

  trace_size = backtrace(trace, 32);
  messages = backtrace_symbols(trace, trace_size);
  fprintf(stderr, "Printing stack frames:\n");
  for (i=0; i < trace_size; ++i)
        fprintf(stderr, "\t%s\n", messages[i]);
}

void panic(char *msg)
{
	fprintf(stderr, "[fire panic] %s\n", msg);
	show_stackframe();
	exit(-1);
}

#ifdef FIRE_PRINT_BUFFER
char *fprint_buffer = NULL;
#define FBUFFER_SIZE		(128L * 1000L * 1000L)
int fprint_lines = 0;
int fprint_head = 0;
struct spinlock fprint_lock;
#endif

void fprint_init()
{
#ifdef FIRE_PRINT_BUFFER
	int i;

	initlock(&fprint_lock);

	fprint_buffer = (char *)malloc(FBUFFER_SIZE);
	if (!fprint_buffer) {
		fprintf(stderr, "failed to initialize fprint buffer\n");
		exit(-1);
	}

	for (i = 0; i < FBUFFER_SIZE; i += 4096)
		fprint_buffer[i] = 'x';
#endif
}

void fprint_fini()
{
#ifdef FIRE_PRINT_BUFFER
	int i, head = 0, len;
	if (fprint_buffer) {
		for (i = 0; i < fprint_lines; i++) {
			len = printf("%s", fprint_buffer + head);
			head += len + 1;
		}
		free(fprint_buffer);
		fprint_buffer = NULL;
	}
#endif
}
