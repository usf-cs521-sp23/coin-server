#include <netdb.h> 
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "common.h"
#include "logger.h"

int main(int argc, char *argv[]) {

	// my machine:
	// localhost
	// 127.0.0.1
	//
    if (argc != 3) {
       printf("Usage: %s hostname port\n", argv[0]);
       return 1;
    }

    char *server_hostname = argv[1];
    int port = atoi(argv[2]);

    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd == -1) {
        perror("socket");
        return 1;
    }

    struct hostent *server = gethostbyname(server_hostname);
    if (server == NULL) {
        fprintf(stderr, "Could not resolve host: %s\n", server_hostname);
        return 1;
    }

    struct sockaddr_in serv_addr = { 0 };
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    serv_addr.sin_addr = *((struct in_addr *) server->h_addr);

    // connect to the server
    if (connect(
                socket_fd,
                (struct sockaddr *) &serv_addr,
                sizeof(struct sockaddr_in)) == -1) {

        perror("connect");
        return 1;
    }

    LOG("Connected to server %s:%d\n", server_hostname, port);

    printf("Welcome. Please type your message below, or press ^D to quit.\n");

    while (true) {
        printf("message> ");
        fflush(stdout);

        char buf[128] = { 0 };
        char *str = fgets(buf, 128, stdin);
        if (str == NULL) {
            LOG("%s", "Reached EOF! Quitting.\n");
            break;
        }

        /* Remove newline characters */
        strtok(buf, "\r\n");
        
        //struct msg_header header;
        //header.msg_len = strlen(buf) + 1;
        //header.msg_type = 0;

        //int written = write_len(socket_fd, &header, sizeof(struct msg_header));
        //LOG("wrote %d bytes\n", written);
        //
        //written = write_len(socket_fd, buf, header.msg_len);
        //LOG("2 wrote %d bytes\n", written);
        
        union msg_wrapper wrapper = create_msg(MSG_SOLUTION);
        struct msg_solution *solution = &wrapper.solution;
        strncpy(solution->username, "matthew", 19);
        solution->nonce = 42;
        
        write_msg(socket_fd, (union msg_wrapper *) solution);
    }

    return 0;
}
