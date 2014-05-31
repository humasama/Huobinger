LIBS = -lpsio -lnuma -lpthread
LIB_DIR = -L../../lib

.PHONY: clean

all: tcp_connect

tcp_connect: tcp_connect.c pkt_buff.c
		gcc -g -o tcp_connect tcp_connect.c pkt_buff.c $(LIB_DIR) $(LIBS)

clean:
	rm -f tcp_connect 
