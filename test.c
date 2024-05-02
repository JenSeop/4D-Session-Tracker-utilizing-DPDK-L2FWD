#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define NSTEK_DEPTH_01_LEN 20000003
#define NSTEK_DEPTH_02_LEN 10000019
#define NSTEK_DEPTH_03_LEN 5000011
#define NSTEK_DEPTH_04_LEN 2500009
#define NSTEK_BYTE_TO_MB 1048576

#define NSTEK_DEPTH_01 1
#define NSTEK_DEPTH_02 2
#define NSTEK_DEPTH_03 3
#define NSTEK_DEPTH_04 4

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

uint32_t depth_01_used = 0;
uint32_t depth_02_used = 0;
uint32_t depth_03_used = 0;
uint32_t depth_04_used = 0;

static uint32_t
nstek_hash(Tuples tuple, int num_of_depth)
{
    uint32_t hash;
    
    hash = (hash * (tuple.ip_01 * tuple.ip_02)) >> (tuple.protocol - num_of_depth);
    hash = (hash * (tuple.port_01 * tuple.port_02)) >> (tuple.protocol - num_of_depth);
    hash = hash & NSTEK_DEPTH_CH(num_of_depth);

    return hash;
}

static void
nstek_tuple_distributor(Tuples target, Tuples entry)
{
    target.ip_01 = entry.ip_01;
    target.ip_02 = entry.ip_02;
    target.port_01 = entry.port_01;
    target.port_02 = entry.port_02;
    target.protocol = entry.protocol;
}

static void
nstek_traffic_distributor(Traffics target, Traffics entry)
{
    target.tx += entry.tx;
    target.rx += entry.rx;
    target.dr += entry.dr;
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
nstek_packet_to_session(Tuples tuple, Traffics traffic, int num_of_depth)
{
    uint32_t hash_index = nstek_hash(tuple, num_of_depth);

    switch (num_of_depth)
    {
        // DEPTH_01
        case NSTEK_DEPTH_01:
            if(depth_01[hash_index].used != 0) // collision!
            {
                if(nstek_compare_session(tuple, depth_01[hash_index].tuple)) // equal session
                {
                    depth_01[hash_index].used += 1;
                    nstek_traffic_distributor(depth_01[hash_index].traffic, traffic);
                }
                else
                {
                    hash_index = nstek_packet_to_session(tuple, traffic, NSTEK_DEPTH_02); // diff session
                    if(hash_index == 0)
                        return 0;
                }
            }
            else // first session
            {
                depth_01[hash_index].used = 1;
                nstek_tuple_distributor(depth_01[hash_index].tuple, tuple);
                nstek_traffic_distributor(depth_01[hash_index].traffic, traffic);
            }
            return hash_index;
        // DEPTH_02
        case NSTEK_DEPTH_02:
            if(depth_02[hash_index].used != 0) // collision!
            {
                if(nstek_compare_session(tuple, depth_02[hash_index].tuple)) // equal session
                {
                    depth_02[hash_index].used += 1;
                    nstek_traffic_distributor(depth_02[hash_index].traffic, traffic);
                }
                else
                {
                    hash_index = nstek_packet_to_session(tuple, traffic, NSTEK_DEPTH_03); // diff session
                    if(hash_index == 0)
                        return 0;
                }
            }
            else // first session
            {
                depth_02[hash_index].used = 1;
                nstek_tuple_distributor(depth_02[hash_index].tuple, tuple);
                nstek_traffic_distributor(depth_02[hash_index].traffic, traffic);
            }
            return hash_index;
        // DEPTH_03
        case NSTEK_DEPTH_03:
            if(depth_03[hash_index].used != 0) // collision!
            {
                if(nstek_compare_session(tuple, depth_03[hash_index].tuple)) // equal session
                {
                    depth_03[hash_index].used += 1;
                    nstek_traffic_distributor(depth_03[hash_index].traffic, traffic);
                }
                else
                {
                    hash_index = nstek_packet_to_session(tuple, traffic, NSTEK_DEPTH_04); // diff session
                    if(hash_index == 0)
                        return 0;
                }
            }
            else // first session
            {
                depth_03[hash_index].used = 1;
                nstek_tuple_distributor(depth_03[hash_index].tuple, tuple);
                nstek_traffic_distributor(depth_03[hash_index].traffic, traffic);
            }
            return hash_index;
        // DEPTH_04
        case NSTEK_DEPTH_04:
            if(depth_04[hash_index].used != 0) // collision!
            {
                if(nstek_compare_session(tuple, depth_04[hash_index].tuple)) // equal session
                {
                    depth_04[hash_index].used += 1;
                    nstek_traffic_distributor(depth_04[hash_index].traffic, traffic);
                }
                else // diff session
                    return 0;
            }
            else // first session
            {
                depth_04[hash_index].used = 1;
                nstek_tuple_distributor(depth_04[hash_index].tuple, tuple);
                nstek_traffic_distributor(depth_04[hash_index].traffic, traffic);
            }
            return hash_index;
    }
    return 0;
}

static void
nstek_session_display()
{
    for(int hash_index = 0; hash_index < NSTEK_DEPTH_CH(NSTEK_DEPTH_01); hash_index++)
    {
        /*
        if(depth_01[hash_index].used != 0)
            printf(
                "%d\t%.3d.%.3d.%.3d.%.3d\t\t%.3d.%.3d.%.3d.%.3d\t\t%d\t%d\t%s\t\t%u\t%u\t%u\n",
                // Hash Table
                hash_index,
                // SRC IP
                (depth_01[hash_index].tuple.ip_01>>0) & 0XFF,(depth_01[hash_index].tuple.ip_01>>8) & 0XFF,
                (depth_01[hash_index].tuple.ip_01>>16) & 0XFF,(depth_01[hash_index].tuple.ip_01>>24) & 0XFF,
                // DST IP
                (depth_01[hash_index].tuple.ip_02>>0) & 0XFF,(depth_01[hash_index].tuple.ip_02>>8) & 0XFF,
                (depth_01[hash_index].tuple.ip_02>>16) & 0XFF,(depth_01[hash_index].tuple.ip_02>>24) & 0XFF,
                // SRC PORT
                NSTEK_REV_ENDIAN(depth_01[hash_index].tuple.port_01),
                // DST PORT
                NSTEK_REV_ENDIAN(depth_01[hash_index].tuple.port_02),
                // PROTOCOL
                NSTEK_PROTOCOL((depth_01[hash_index].tuple.protocol)),
                // TX
                depth_01[hash_index].traffic.tx,
                // RX
                depth_01[hash_index].traffic.rx,
                // DR
                depth_01[hash_index].traffic.dr
            );
        */
    }
}

static int
nstek_target_depth_init(HashTables *ptr_of_depth, int num_of_depth)
{
    ptr_of_depth = (HashTables*)malloc(NSTEK_DEPTH_CH(num_of_depth) * sizeof(HashTables));

    if(ptr_of_depth == NULL)
    {
        printf("[NSTEK ERROR] DEPTH_%.2d [%.8d] %.3d MB Memory allocation failed.\n", num_of_depth, NSTEK_DEPTH_CH(num_of_depth), (sizeof(ptr_of_depth[NSTEK_DEPTH_CH(num_of_depth)]) * NSTEK_DEPTH_CH(num_of_depth) / NSTEK_BYTE_TO_MB));
        exit(1);
    }
    else
    {
        printf("[NSTEK] DEPTH_%.2d [%.8d] %.3d MB Memory allocation successful.\n", num_of_depth, NSTEK_DEPTH_CH(num_of_depth), (sizeof(ptr_of_depth[NSTEK_DEPTH_CH(num_of_depth)]) * NSTEK_DEPTH_CH(num_of_depth) / NSTEK_BYTE_TO_MB));
        return (sizeof(ptr_of_depth[0]) * NSTEK_DEPTH_CH(num_of_depth) / NSTEK_BYTE_TO_MB);
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

    printf("[NSTEK] DEPTH_%.2d [%.8d] %.3d MB Memory deallocation successful.\n",num_of_depth, NSTEK_DEPTH_CH(num_of_depth), (sizeof(ptr_of_depth[0]) * NSTEK_DEPTH_CH(num_of_depth) / NSTEK_BYTE_TO_MB));
    return (sizeof(ptr_of_depth[0]) * NSTEK_DEPTH_CH(num_of_depth) / NSTEK_BYTE_TO_MB);
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
    Tuples tuple = {3232235521, 3232235522, 1024, 1025, 6};
    Traffics traffic = {0, 0, 0};
    uint32_t hash_index;

    nstek_all_depth_init();

    printf("hash = %d\n",nstek_packet_to_session(tuple,traffic,NSTEK_DEPTH_01));
    printf("hash = %d\n",nstek_packet_to_session(tuple,traffic,NSTEK_DEPTH_02));

    hash_index = 1953786;

    hash_index = 7814864;

    nstek_session_display();

    nstek_all_depth_free();

    return 0;
}