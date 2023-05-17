#ifndef TASK_H
#define TASK_H

#define MAX_BLOCK_LEN 128

void task_init(int seed, char* adjective_file, char* animal_file);
void task_generate(char buf[MAX_BLOCK_LEN]);
void task_destroy();

#endif