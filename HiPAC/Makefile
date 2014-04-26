LIBS = -lpsio -lnuma
LIB_DIR = -L../Packet-IO-Engine/lib
IOENGINE_DIR = -I../Packet-IO-Engine/include
HEAD_DIR = -I./include

.PHONY: clean

all: hipac

hipac: hipac.c
	gcc -c hipac.c $(IOENGINE_DIR) $(HEAD_DIR) $(LIB_DIR)
	ar rcs libhipac.a hipac.o

clean:
	rm -f hipac libhipac.a hipac.o

