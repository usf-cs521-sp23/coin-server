#ifndef SERVER_H
#define SERVER_H

#ifndef VERSION
#define VERSION 1.0
#endif

void *client_thread(void* client_fd);

#endif
