include fire.mk

CC = gcc
#CFLAGS = -Wall -g -D__USE_GNU -D_GNU_SOURCE -DMAX_WORKER_NUM=8
CFLAGS		= -g -D__USE_GNU -D_BSD_SOURCE
CFLAGS		+= -DLIBNET_VER=-1 -DHAVE_ICMPHDR=1 -DHAVE_TCP_STATES=1 -DHAVE_BSD_UDPHDR=1 
CFLAGS		+= $(FIRE_CONFIGS) -DFIRE_PRINT_LEVEL=$(PRINT_LEVEL)

#LIBS = -lrt -lnuma -L../Packet-IO-Engine/lib -lpsio -lpthread
LIBS = -lrt -lnuma -L../Packet-IO-Engine/lib -lpsio -L../HiPAC -lhipac -lpthread

HEADER_DIR = ./include 
IOENGINE_DIR = ../Packet-IO-Engine/include
HIPAC_DIR = ../HiPAC/include
OBJECT_DIR = objs
TARGET_DIR = .

TARGET_FILE = firewall 
TARGET = $(addprefix $(TARGET_DIR)/, $(TARGET_FILE))

SOURCE_FILES = $(wildcard *.c)
HEADER_FILES = $(wildcard *.h) $(wildcard *.h)
OBJECT_FILE = $(SOURCE_FILES:.c=.o)

OBJECT = $(addprefix $(OBJECT_DIR)/, $(OBJECT_FILE))

all: $(OBJECT_DIR) $(TARGET)

$(TARGET): $(OBJECT) | $(TARGET_DIR) $(OBJECT_DIR)
	$(CC) $(OBJECT) -o $@ $(LIBS) -pg

$(OBJECT_DIR):
	mkdir $(OBJECT_DIR)


$(OBJECT_DIR)/%.o : %.c
	$(CC) $(CFLAGS) -I $(HEADER_DIR) -I $(IOENGINE_DIR) -I $(HIPAC_DIR) -c $< -o $@ -pg

.PHONY : clean
clean:
	rm -rf $(TARGET) $(OBJECT)

doc: $(SOURCE_FILES) doxygen.config
	doxygen doxygen.config
