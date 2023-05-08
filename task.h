#ifndef TASK_H
#define TASK_H

#define MAX_BLOCK_LEN 128

void task_init(int seed);
void task_generate(char buf[MAX_BLOCK_LEN]);

#endif