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

/** [05/07/23 InhwaS] ---------- start ---------- */
// Since we updated char *array[] into dynamic array, 
//       we need pointer to dynamic array(**char) as a parameter which is "***char"
size_t read_file(char filename[], char ***array);

// char *animals[] = {...}
// char *adjectives[] = {...}
// ==> changed into dynamic array 
char **animals;
char **adjectives;

// const size_t adj_sz = sizeof(adjectives) / sizeof(char *);
// const size_t ani_sz = sizeof(animals) / sizeof(char *);
// ==> changed const variable because we need to calculate them from the task_init() function.
size_t adj_sz = 0; 
size_t ani_sz = 0;
/** [05/07/23 InhwaS] ---------- end ---------- */

void task_init()
{
    /** [05/07/23 InhwaS] ---------- start ---------- */
    ani_sz = read_file("animals", &animals);
    LOG("finished reading animals. animal array size [%zu]\n", ani_sz);

    adj_sz = read_file("adjectives", &adjectives);
    LOG("finished reading adjectives. adjective array size [%zu]\n", adj_sz);
    
    LOG("Initializing task generator. %zu animals, %zu adjectives (%zu x %zu = %zu)\n", ani_sz, adj_sz, ani_sz, adj_sz, adj_sz * ani_sz);
    srand(time(NULL));
    /** [05/07/23 InhwaS] ---------- end ---------- */

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
    assert(longest_task_len < MAX_TASK_LEN);
    
    LOGP("Shuffling animals.\n");
    fisher_yates(animals, ani_sz);

    LOGP("Shuffling adjectives.\n");
    fisher_yates(adjectives, ani_sz);
    
    LOGP("Task generator ready.\n");
}

void task_generate(char buf[MAX_TASK_LEN])
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

/** [05/07/23 InhwaS] ---------- start ---------- */
size_t read_file(char filename[], char ***array){
    FILE *file = fopen(filename, "r");
    if ( file == NULL ){
        perror("fopen for file");
    }

    char buf[128] = { 0 };
    int i = 0;
    while (fgets(buf, sizeof(buf), file) != NULL) {
        i++;
    }
    *array = malloc(i * sizeof(char*));
    fclose(file);   

    i = 0;
    FILE *file_again = fopen(filename, "r");
    while (fgets(buf, sizeof(buf), file_again) != NULL) {
        strtok(buf, "\r\n");
        
        (*array)[i] = strdup(buf);
        i++;
    }
    fclose(file_again);   
    return i;
}

int main(void){
    task_init();
}
/** [05/07/23 InhwaS] ---------- end ---------- */