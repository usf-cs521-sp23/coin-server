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
#include "sha1.h"

#define MAX_USERS 100
#define USERNAME_LENGTH 20

static char current_block[MAX_BLOCK_LEN];
static uint32_t current_difficulty = 0x0000FFF;

struct user_info {
    char username[USERNAME_LENGTH];
    uint32_t wins;
};

static struct user_info leaderboard[MAX_USERS];
static int num_users = 0;

void update_leaderboard(char *username) {
    int user_index = -1;
    // find user in leaderboard
    for (int i = 0; i < num_users; i++) {
        if (strcmp(leaderboard[i].username, username)) {
            user_index = i;
            break;
        }
    }
    if (user_index == -1) {
        if (num_users < MAX_USERS) {
            strncpy(leaderboard[num_users].username, username, USERNAME_LENGTH - 1);
            leaderboard[num_users].wins = 1;
            num_users++;
        } else {
            printf("Leaderboard is full\n");
            EXIT_FAILURE;
        }
    } else {
        leaderboard[user_index].wins++;
    }

}

void handle_request_task(int fd, struct msg_request_task *req)
{
    LOG("[TASK REQUEST] User: %s, block: %s, difficulty: %u\n", req->username, current_block, current_difficulty);
    union msg_wrapper wrapper = create_msg(MSG_TASK);
    struct msg_task *task = &wrapper.task;
    strcpy(task->block, current_block);
    task->difficulty = current_difficulty;

    write_msg(fd, &wrapper);
}

bool verify_solution(struct msg_solution *solution)
{
    uint8_t digest[SHA1_HASH_SIZE];
    const char *check_format = "%s%lu";
    ssize_t buf_sz = snprintf(NULL, 0, check_format, current_block, solution->nonce);
    char *buf = malloc(buf_sz + 1);
    snprintf(buf, buf_sz + 1, check_format, current_block, solution->nonce);
    sha1sum(digest, (uint8_t *) buf, buf_sz);
    char hash_string[521];
    sha1tostring(hash_string, digest);
    LOG("SHA1sum: '%s' => '%s'\n", buf, hash_string);
    free(buf);

    /* Get the first 32 bits of the hash */
    uint32_t hash_front = 0;
    hash_front |= digest[0] << 24;
    hash_front |= digest[1] << 16;
    hash_front |= digest[2] << 8;
    hash_front |= digest[3];

    /* Check to see if we've found a solution to our block */
    return (hash_front & current_difficulty) == hash_front;
}

void handle_solution(int fd, struct msg_solution *solution)
{
    LOG("[SOLUTION SUBMITTED] User: %s, block: %s, difficulty: %u, NONCE: %lu\n", solution->username, solution->block, solution->difficulty, solution->nonce);
    
    union msg_wrapper wrapper = create_msg(MSG_VERIFICATION);
    struct msg_verification *verification = &wrapper.verification;
    verification->ok = false; // assume the solution is not valid by default

    /* We could directly verify the solution, but let's make sure it's the same
     * block and difficulty first: */
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

    verification->ok = verify_solution(solution);
    strcpy(verification->error_description, "Verified SHA-1 hash");
    write_msg(fd, &wrapper);
    LOG("[SOLUTION %s!]\n", verification->ok ? "ACCEPTED" : "REJECTED");
    
    if (verification->ok) {
        update_leaderboard(solution->username);
        task_generate(current_block);
        LOG("Generated new block: %s\n", current_block);
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
//
      union msg_wrapper msg;
       if (read_msg(fd, &msg) <= 0) {
           LOGP("Disconnecting client\n");
        return NULL;
       }
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

    if (argc < 2) {
        printf("Usage: %s port [seed]\n", argv[0]);
        return 1;
    }
    
    int seed = 0;
    if (argc == 3) {
        char *end;
        seed = strtol(argv[2], &end, 10);
        if (end == argv[2]) {
            fprintf(stderr, "Invalid seed: %s\n", argv[2]);
        }
    }
    
    LOG("Starting coin-server version %.1f...\n", VERSION);
    LOG("%s", "(c) 2023 CS 521 Students\n");
    
    task_init(seed);
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
