LIBS := -lpsio -lnuma -lpthread
LIB_DIR := -L../lib
INC := -I../include
CFLAGS := -O2 -g -Wall $(INC)
ifdef EPOLL
CFLAGS := $(CFLAGS) -DUSE_EPOLL
endif

.PHONY: clean

all: multiThread

multiThread: multiThread.c
	gcc $(CFLAGS) -o multiThread multiThread.c $(LIB_DIR) $(LIBS)

clean:
	rm -f multiThread
