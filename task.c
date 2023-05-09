/*
 * Change Log:
 * e.g. [DD/MM/YY Writer]: Description of another change
 * 
 * [05/07/23 InhwaS]: issue#2 split the "animals" array and the "adjectives" array into separate files
 * 
 */
#include "task.h"
#include "logger.h"

#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

static size_t ani_idx = 0;
static size_t adj_idx = 0;

void fisher_yates(char *arr[], size_t sz);

size_t read_file(char filename[], char ***array);

char **animals;
char **adjectives;

static size_t adj_sz = 0; 
static size_t ani_sz = 0;

/**
 * Seeds the random number generator and then sets up task generation data
 * structures by shuffling task components.
 */
void task_init(int seed)
{
    ani_sz = read_file("animals", &animals);
    adj_sz = read_file("adjectives", &adjectives);
    
    LOG("Initializing task generator. %zu animals, %zu adjectives (%zu x %zu = %zu)\n", ani_sz, adj_sz, ani_sz, adj_sz, adj_sz * ani_sz);

    if (seed == 0) {
        seed = time(NULL);
    }
    LOG("Random seed: %d\n", seed);
    srand(seed);

    size_t max_ani_len = 0;
    for (int i = 0; i < ani_sz; ++i)
    {
        size_t len = strlen(animals[i]);
        if (len > max_ani_len) {
            max_ani_len = len;
        }
    }
    LOG("Longest animal length: %zu\n", max_ani_len);

    size_t max_adj_len = 0;
    for (int i = 0; i < adj_sz; ++i)
    {
        size_t len = strlen(adjectives[i]);
        if (len > max_adj_len) {
            max_adj_len = len;
        }
    }
    LOG("Longest adjective length: %zu\n", max_adj_len);

    size_t longest_task_len = max_ani_len + max_adj_len + 1;
    assert(longest_task_len < MAX_BLOCK_LEN);
    
    LOGP("Shuffling animals.\n");
    fisher_yates(animals, ani_sz);

    LOGP("Shuffling adjectives.\n");
    fisher_yates(adjectives, ani_sz);
    
    LOGP("Task generator ready.\n");
}

void task_generate(char buf[MAX_BLOCK_LEN])
{
    sprintf(buf, "%s %s", adjectives[adj_idx++], animals[ani_idx++]);
    
    // roll over animals / adjectives on overflow
    if (adj_idx == adj_sz) {
        adj_idx = 0;
    }
    
    if (ani_idx == ani_sz) {
        ani_idx = 0;
    }
}

void fisher_yates(char *arr[], size_t sz)
{
    for (int i = sz - 1; i > 0; i--) {
        int r = rand() % (i + 1);
        char *temp = arr[r];
        arr[r] = arr[i];
        arr[i] = temp;
    }
}

size_t read_file(char filename[], char ***array){
    FILE *file = fopen(filename, "r");
    if ( file == NULL ){
        perror("fopen for file");
    }

    /* Determine the number of lines in the file */
    char buf[MAX_BLOCK_LEN] = { 0 };
    int i = 0;
    while (fgets(buf, sizeof(buf), file) != NULL) {
        i++;
    }
    *array = malloc(i * sizeof(char *));

    /* Read the contents */
    fseek(file, 0L, SEEK_SET);
    i = 0;
    while (fgets(buf, sizeof(buf), file) != NULL) {
        strtok(buf, "\r\n");
        
        (*array)[i] = strdup(buf);
        i++;
    }
    fclose(file);   
    return i;
}