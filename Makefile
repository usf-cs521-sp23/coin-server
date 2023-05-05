# Output binary name
bin=coin-server

# Set the following to '0' to disable log messages:
LOGGER ?= 1
VERSION = 1.0

# Compiler/linker flags
CFLAGS += -g -Wall -DLOGGER=$(LOGGER) -DVERSION=$(VERSION)
LDLIBS +=
LDFLAGS +=

src=server.c common.c
obj=$(src:.c=.o)

all: $(bin)

$(bin): $(obj)
	$(CC) $(CFLAGS) $(LDLIBS) $(LDFLAGS) $(obj) -o $@

server.o: server.h server.c common.o logger.h
common.o: common.h logger.h

clean:
	rm -f $(bin) $(obj) vgcore.*

