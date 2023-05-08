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

static char current_block[MAX_BLOCK_LEN];
static uint32_t current_difficulty = 0x0000FFF;

void handle_request_task(int fd, struct msg_request_task *req)
{
    LOG("[TASK REQUEST] User: %s, block: %s, difficulty: %u\n", req->username, current_block, current_difficulty);
    union msg_wrapper wrapper = create_msg(MSG_TASK);
    struct msg_task *task = &wrapper.task;
    strcpy(task->block, current_block);
    task->difficulty = current_difficulty;

    write_msg(fd, &wrapper);
}

void handle_solution(int fd, struct msg_solution *solution)
{
    LOG("[SOLUTION SUBMITTED] User: %s, block: %s, difficulty: %u, NONCE: %lu\n", solution->username, solution->block, solution->difficulty, solution->nonce);
    
    union msg_wrapper wrapper = create_msg(MSG_VERIFICATION);
    struct msg_verification *verification = &wrapper.verification;
    verification->ok = false; // assume the solution is not valid by default

    if (strcmp(current_block, solution->block) != 0)
    {
        strcpy(verification->error_description, "Block does not match current block on server");
        write_msg(fd, &wrapper);
        return;
    }
    
    if (current_difficulty !=  solution->difficulty) {
        strcpy(verification->error_description, "Difficulty does not match current difficulty on server");
        write_msg(fd, &wrapper);
        return;
    }
    
}

void *client_thread(void* client_fd) {
    int fd = (int) (long) client_fd;
    while (true) {
//        struct msg_header header;
//        read_len(fd, &header, sizeof(struct msg_header));
//        struct msg_solution solution;
//        void *sol_ptr = (char *) &solution + sizeof(struct msg_header);
//        read_len(fd, sol_ptr, header.msg_len - sizeof(struct msg_header));
        union msg_wrapper msg = read_msg(fd);
        switch (msg.header.msg_type) {
            case MSG_REQUEST_TASK: handle_request_task(fd, (struct msg_request_task *) &msg.request_task);
                                   break;
            case MSG_SOLUTION: handle_solution(fd, (struct msg_solution *) &msg.solution);
                               break;
            default:
                LOG("ERROR: unknown message type: %d\n", msg.header.msg_type);
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
    task_generate(current_block);
    LOG("Current block: %s\n", current_block);

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
