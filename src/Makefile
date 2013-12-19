include fire.mk

CC = gcc
#CFLAGS = -Wall -g -D__USE_GNU -D_GNU_SOURCE -DMAX_WORKER_NUM=8
CFLAGS		= -O2 -lpthread -D__USE_GNU -D_BSD_SOURCE
CFLAGS		+= -DLIBNET_VER=-1 -DHAVE_ICMPHDR=1 -DHAVE_TCP_STATES=1 -DHAVE_BSD_UDPHDR=1 
CFLAGS		+= $(FIRE_CONFIGS)

LIBS = -lrt -lpthread -L../Packet-IO-Engine/lib -lpsio

HEADER_DIR = ./include 
IOENGINE_DIR = ../Packet-IO-Engine/include
OBJECT_DIR = objs
TARGET_DIR = .

TARGET_FILE = firewall 
TARGET = $(addprefix $(TARGET_DIR)/, $(TARGET_FILE))

SOURCE_FILES = $(wildcard *.c)
HEADER_FILES = $(wildcard *.h) $(wildcard *.h)
OBJECT_FILE = $(SOURCE_FILES:.c=.o)

OBJECT = $(addprefix $(OBJECT_DIR)/, $(OBJECT_FILE))

all: $(TARGET)

$(TARGET): $(OBJECT) | $(TARGET_DIR) $(OBJECT_DIR)
	$(CC) -pg $(OBJECT) -o $@ $(LIBS) $(LDFLAGS)

$(OBJECT_DIR):
	mkdir $(OBJECT_DIR)


$(OBJECT_DIR)/%.o : %.c
	$(CC) -pg $(CFLAGS) -I $(HEADER_DIR) -I $(IOENGINE_DIR) -c $< -o $@

.PHONY : clean
clean:
	rm -rf $(TARGET) $(OBJECT)

doc: $(SOURCE_FILES) doxygen.config
	doxygen doxygen.config
