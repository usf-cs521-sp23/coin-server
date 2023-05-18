#ifndef TASK_H
#define TASK_H

#define MAX_BLOCK_LEN 128

struct msg_solution;

void task_init(char* adjective_file, char* animal_file);
void task_generate(char buf[MAX_BLOCK_LEN]);
void task_destroy();
void task_log_open(char *file);
void task_log_add(struct msg_solution *solution);
void task_log_close(void);

#endif