all: client server

CFLAGS += -Wall -g

client: client.c common.h common.o
	$(CC) $(LDFLAGS) $(CFLAGS) client.c common.o -o client

server: server.c common.h common.o
	$(CC) $(LDFLAGS) $(CFLAGS) server.c common.o -o server

common.o: common.c common.h

clean:
	rm -rf client server common.o
