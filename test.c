#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define NSTEK_DEPTH_01_LEN 20000003
#define NSTEK_DEPTH_02_LEN 10000019
#define NSTEK_DEPTH_03_LEN 5000011
#define NSTEK_DEPTH_04_LEN 2500009
#define BYTE_TO_MB 1048576

#define NSTEK_DEPTH_CH(n) ((n == 1) ? NSTEK_DEPTH_01_LEN : (n == 2) ? NSTEK_DEPTH_02_LEN : (n == 3) ? NSTEK_DEPTH_03_LEN : (n == 4) ? NSTEK_DEPTH_04_LEN : 0)
#define NSTEK_PROTOCOL(n) ((n) == 1 ? "ICMP" : (n) == 2 ? "IGMP" : (n) == 6 ? "TCP" : (n) == 17 ? "UDP" : (n) == 114 ? "Any 0-hop" : "N/A")
#define NSTEK_REV_ENDIAN(n) ((uint16_t)(((n) >> 8) | (n) << 8))

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
    uint32_t used;
    Tuples tuple;
    Traffics traffic;
} HashTables;

HashTables *depth_01;
HashTables *depth_02;
HashTables *depth_03;
HashTables *depth_04;

static uint32_t
nstek_hash(Tuples entry, int num_of_depth)
{
    uint32_t hash = 5381;

    hash = ((hash << (4 + num_of_depth)) + hash) ^ (entry.ip_01 << 24) ^ (entry.ip_02 << 24);
    hash = ((hash << (4 + num_of_depth)) + hash) ^ (entry.ip_01 << 16) ^ (entry.ip_02 << 16);
    hash = ((hash << (4 + num_of_depth)) + hash) ^ (entry.ip_01 << 8) ^ (entry.ip_02 << 8);
    hash = ((hash << (4 + num_of_depth)) + hash) ^ (entry.ip_01 << 0) ^ (entry.ip_02 << 0);
    hash = ((hash << (4 + num_of_depth)) + hash) ^ (entry.port_01) ^ (entry.protocol);
    hash = ((hash << (4 + num_of_depth)) + hash) ^ (entry.port_02) ^ (entry.protocol);

    return hash % NSTEK_DEPTH_CH(num_of_depth);
}

static int
nstek_compare_session(Tuples entry, Tuples existence)
{
    return
    (
        // IP
        ((
            ((((entry.ip_01 == existence.ip_01)) && ((entry.ip_02 == existence.ip_02)))) ||
            ((((entry.ip_01 == existence.ip_02)) && ((entry.ip_02 == existence.ip_01))))
        )) &&
        // Port
        ((
            ((((entry.port_01 == existence.port_01)) && ((entry.port_02 == existence.port_02)))) ||
            ((((entry.port_01 == existence.port_02)) && ((entry.port_02 == existence.port_01))))
        )) &&
        // Protocol
        ((
            ((entry.protocol == existence.protocol))
        ))
    );
}

static int
nstek_target_depth_init(HashTables *ptr_of_depth, int num_of_depth)
{
    ptr_of_depth = (HashTables*)malloc(NSTEK_DEPTH_CH(num_of_depth) * sizeof(HashTables));

    if(ptr_of_depth == NULL)
    {
        printf("[NSTEK ERROR] DEPTH_%.2d [%.8d] %.3d MB Memory allocation failed.\n", num_of_depth, NSTEK_DEPTH_CH(num_of_depth), (sizeof(ptr_of_depth[NSTEK_DEPTH_CH(num_of_depth)]) * NSTEK_DEPTH_CH(num_of_depth) / BYTE_TO_MB));
        exit(1);
    }
    else
    {
        printf("[NSTEK] DEPTH_%.2d [%.8d] %.3d MB Memory allocation successful.\n", num_of_depth, NSTEK_DEPTH_CH(num_of_depth), (sizeof(ptr_of_depth[NSTEK_DEPTH_CH(num_of_depth)]) * NSTEK_DEPTH_CH(num_of_depth) / BYTE_TO_MB));
        return (sizeof(ptr_of_depth[0]) * NSTEK_DEPTH_CH(num_of_depth) / BYTE_TO_MB);
    }

    return 0;
}

static int
nstek_all_depth_init()
{
    int total_volume = 0;

    total_volume += nstek_target_depth_init(depth_01, 1);
    total_volume += nstek_target_depth_init(depth_02, 2);
    total_volume += nstek_target_depth_init(depth_03, 3);
    total_volume += nstek_target_depth_init(depth_04, 4);

    printf("[NSTEK] TOTAL_DEPTH_VOLUME %.4d MB Memory allocation successful.\n", total_volume);
    return total_volume;
}

static int
nstek_target_depth_free(HashTables *ptr_of_depth, int num_of_depth)
{
    free(ptr_of_depth);

    printf("[NSTEK] DEPTH_%.2d [%.8d] %.3d MB Memory deallocation successful.\n",num_of_depth, NSTEK_DEPTH_CH(num_of_depth), (sizeof(ptr_of_depth[0]) * NSTEK_DEPTH_CH(num_of_depth) / BYTE_TO_MB));
    return (sizeof(ptr_of_depth[0]) * NSTEK_DEPTH_CH(num_of_depth) / BYTE_TO_MB);
}

static int
nstek_all_depth_free()
{
    int total_volume = 0;

    total_volume += nstek_target_depth_free(depth_01, 1);
    total_volume += nstek_target_depth_free(depth_02, 2);
    total_volume += nstek_target_depth_free(depth_03, 3);
    total_volume += nstek_target_depth_free(depth_04, 4);

    printf("[NSTEK] TOTAL_DEPTH_VOLUME %.4d MB Memory deallocation successful.\n", total_volume);
    return total_volume;
}

int main(void)
{
    nstek_all_depth_init();
    nstek_all_depth_free();

    Tuples tuple = {3232235521, 3232235522, 1024, 1025, 6};
    printf("return = %d\n",nstek_hash(tuple, 1));
    printf("return = %d\n",nstek_hash(tuple, 2));
    printf("return = %d\n",nstek_hash(tuple, 3));
    printf("return = %d\n",nstek_hash(tuple, 4));

    return 0;
}