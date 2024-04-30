#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define DEPTH_01_LEN 20000003
#define DEPTH_02_LEN 10000019
#define DEPTH_03_LEN 5000011
#define DEPTH_04_LEN 2500009

#define DEPTH_CH(n) ((n == 1) ? DEPTH_01_LEN : (n == 2) ? DEPTH_02_LEN : (n == 3) ? DEPTH_03_LEN : (n == 4) ? DEPTH_04_LEN : 0)

typedef struct
Traffics {
    uint32_t tx;
    uint32_t rx;
    uint32_t dr;
} Traffics;

typedef struct
Tuples {
    uint32_t ip_01;
    uint32_t ip_02;
    uint32_t port_01;
    uint32_t port_02;
    uint32_t protocol;
} Tuples;

typedef struct
HashTables {

    uint32_t session_cnt;
    Tuples tuple;
    Traffics traffic;

} HashTables;

HashTables *depth_01;
HashTables *depth_02;
HashTables *depth_03;
HashTables *depth_04;

void nstek_target_depth_init(HashTables *ptr_of_depth, int num_of_depth)
{
    ptr_of_depth = (HashTables*)malloc(DEPTH_CH(num_of_depth) * sizeof(HashTables));
    if(ptr_of_depth == NULL)
    {
        printf("[NSTEK] DEPTH_%.2d[%.8d] Memory allocation failed.\n", num_of_depth, DEPTH_CH(num_of_depth));
        exit(1);
    }
    else
    {
        printf("[NSTEK] DEPTH_%.2d[%.8d] Memory allocation successful.\n",num_of_depth, DEPTH_CH(num_of_depth));
    }
}

void nstek_all_depth_init()
{
    nstek_target_depth_init(depth_01, 1);
    nstek_target_depth_init(depth_02, 2);
    nstek_target_depth_init(depth_03, 3);
    nstek_target_depth_init(depth_04, 4);
}

void nstek_target_depth_free(HashTables *depth, int num_of_depth)
{
    free(depth);
    printf("[NSTEK] DEPTH_%.2d[%.8d] Memory deallocation successful.\n",num_of_depth, DEPTH_CH(num_of_depth));
}

void nstek_all_depth_free()
{
    nstek_target_depth_free(depth_01, 1);
    nstek_target_depth_free(depth_02, 2);
    nstek_target_depth_free(depth_03, 3);
    nstek_target_depth_free(depth_04, 4);
}

int main(void)
{
    nstek_all_depth_init();
    nstek_all_depth_free();

    return 0;
}