#include "server.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h> 
#include <unistd.h>
#include <pthread.h>

#include "common.h"
#include "logger.h"
#include "task.h"

static char current_task[MAX_TASK_LEN];

void *client_thread(void* client_fd) {
    int fd = (int) (long) client_fd;
    while (true) {
//        struct msg_header header;
//        read_len(fd, &header, sizeof(struct msg_header));
//        struct msg_solution solution;
//        void *sol_ptr = (char *) &solution + sizeof(struct msg_header);
//        read_len(fd, sol_ptr, header.msg_len - sizeof(struct msg_header));
        union msg_wrapper msg = read_msg(fd);
        if (msg.header.msg_type == MSG_SOLUTION) {
            printf("-> %s , nonce: %lu\n", msg.solution.username, msg.solution.nonce);
            
            // verify solution

            // tell the client it was ok / not ok
        }
         if (msg.header.msg_type == MSG_TASK) {
            // give them a task

            //etc
         }
    }
    
    /* Server checklist:
     * 
     * - Figure out what the blocks are that the clients will solve
     *      ravishing dijkstra
     *      alive koala
     * - Hand out tasks
     * - Verify tasks
     * - Keep track of everybody's money and send it to Matthew
     */

    return NULL;
}


int main(int argc, char *argv[]) {

    if (argc != 2) {
        printf("Usage: %s port\n", argv[0]);
        return 1;
    }
    
    LOG("Starting coin-server version %.1f...\n", VERSION);
    LOG("%s", "(c) 2023 CS 521 Students\n");
    
    task_init();
    
    task_generate(current_task);
    LOG("Current task: %s\n", current_task);

    int port = atoi(argv[1]);

    // create a socket
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd == -1) {
        perror("socket");
        return 1;
    }

    // bind to the port specified above
    struct sockaddr_in addr = { 0 };
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    if (bind(socket_fd, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
        perror("bind");
        return 1;
    }

    // start listening for clients to connect
    if (listen(socket_fd, 10) == -1) {
        perror("listen");
        return 1;
    }

    LOG("Listening on port %d\n", port);

    while (true) {
        /* Outer loop: this keeps accepting connection */
        struct sockaddr_in client_addr = { 0 };
        socklen_t slen = sizeof(client_addr);

	// accept client connection
        int client_fd = accept(
                socket_fd,
                (struct sockaddr *) &client_addr,
                &slen);

        if (client_fd == -1) {
            perror("accept");
            return 1;
        }

	// find out their info (host name, port)
        char remote_host[INET_ADDRSTRLEN];
        inet_ntop(
                client_addr.sin_family,
                (void *) &((&client_addr)->sin_addr),
                remote_host,
                sizeof(remote_host));
        LOG("Accepted connection from %s:%d\n", remote_host, client_addr.sin_port);

        pthread_t thread;
        pthread_create(&thread, NULL, client_thread, (void *) (long) client_fd);
        pthread_detach(thread);
    }

    return 0; 
}
