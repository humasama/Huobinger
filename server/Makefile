LIBS = -lpsio -lnuma
LIB_DIR = -L../../lib

.PHONY: clean

all: tcp_connect

tcp_connect: tcp_connect.c
		gcc -g -o tcp_connect tcp_connect.c $(LIB_DIR) $(LIBS)

clean:
	rm -f tcp_connect 
