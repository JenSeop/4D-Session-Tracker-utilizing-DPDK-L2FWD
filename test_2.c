#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define NSTEK_DEPTH 4
#define NSTEK_DEPTH_01 0
#define NSTEK_DEPTH_02 1
#define NSTEK_DEPTH_03 2
#define NSTEK_DEPTH_04 3

#define NSTEK_DEPTH_01_LN 20000003
#define NSTEK_DEPTH_02_LN 10000019
#define NSTEK_DEPTH_03_LN 5000011
#define NSTEK_DEPTH_04_LN 2500009

#define NSTEK_DEPTH_01_DR 11
#define NSTEK_DEPTH_02_DR 13
#define NSTEK_DEPTH_03_DR 17
#define NSTEK_DEPTH_04_DR 29

#define NSTEK_BYTE_TO_MB 1048576

#define NSTEK_DEPTH_LN_CH(n) ((n == 0) ? NSTEK_DEPTH_01_LN : (n == 1) ? NSTEK_DEPTH_02_LN : (n == 2) ? NSTEK_DEPTH_03_LN : (n == 3) ? NSTEK_DEPTH_04_LN : 0)
#define NSTEK_DEPTH_DR_CH(n) ((n == 0) ? NSTEK_DEPTH_01_DR : (n == 1) ? NSTEK_DEPTH_02_DR : (n == 2) ? NSTEK_DEPTH_03_DR : (n == 3) ? NSTEK_DEPTH_04_DR : 0)
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
    uint32_t src_addr;
    uint32_t dst_addr;
    uint32_t src_port;
    uint32_t dst_port;
    uint32_t protocol;
} Tuples;

typedef struct
HashTables {
    uint32_t used;
    Tuples tuple;
    Traffics traffic;
} HashTables;

HashTables **hash_table;

/*
    NSTEK_HASH
    Standard Multiplicative Hashing Custom Model
    
    DEPTH 1 - 65025(255 * 255) repetitions, 116 collisions.
              Collision incidence 0.16147635524798157.
              percentage = 0.1%

    DEPTH 2 - 65025(255 * 255) repetitions, 211 collisions.
              Collision incidence 0.3244905805459439.
              percentage = 0.3%
    
    DEPTH 3 - 65025(255 * 255) repetitions, 394 collisions.
              Collisions incidence 0.605920799692426.
              percentage = 0.6%

    DEPTH 4 - 65025(255 * 255) repetitions, 838 collisions.
              Collisions incidence 1.2887351018838908.
              percentage = 1.2%
    
    DEPTH AVERAGE COLLISION PERCENT 0.55% 
*/

static uint32_t
nstek_hash(Tuples tuple, int depth)
{
    uint32_t hash = NSTEK_DEPTH_DR_CH(depth);
    
    hash = (~hash * ~(tuple.src_addr * tuple.dst_addr)) >> (~depth + tuple.protocol);
    hash = (~hash * ~(~tuple.src_port * ~tuple.dst_port)) >> (~depth + tuple.protocol);
    hash = hash % NSTEK_DEPTH_LN_CH(depth);

    return hash;
}

static int
nstek_compare_session(Tuples entry, Tuples existence)
{
    return
    (
        // IP
        ((
            ((((entry.src_addr == existence.src_addr)) && ((entry.dst_addr == existence.dst_addr)))) ||
            ((((entry.src_addr == existence.dst_addr)) && ((entry.dst_addr == existence.src_addr))))
        )) &&
        // Port
        ((
            ((((entry.src_port == existence.src_port)) && ((entry.dst_port == existence.dst_port)))) ||
            ((((entry.src_port == existence.dst_port)) && ((entry.dst_port == existence.src_port))))
        )) &&
        // Protocol
        ((
            ((entry.protocol == existence.protocol))
        ))
    );
}

static void
nstek_traffic_distributor(int depth, uint32_t hash_index, Traffics traffic)
{
    hash_table[depth][hash_index].traffic.tx += traffic.tx;
    hash_table[depth][hash_index].traffic.rx += traffic.rx;
    hash_table[depth][hash_index].traffic.dr += traffic.dr;
}

static void
nstek_tuple_distributor(int depth, uint32_t hash_index, Tuples tuple)
{
    hash_table[depth][hash_index].tuple.src_addr = tuple.src_addr;
    hash_table[depth][hash_index].tuple.dst_addr = tuple.dst_addr;
    hash_table[depth][hash_index].tuple.src_port = tuple.src_port;
    hash_table[depth][hash_index].tuple.dst_port = tuple.dst_port;
    hash_table[depth][hash_index].tuple.protocol = tuple.protocol;
}

static int
nstek_packet_to_session(Tuples tuple, Traffics traffic, int depth)
{
    uint32_t hash_index = nstek_hash(tuple, depth);

    if(depth > NSTEK_DEPTH)
    {
        printf("[NSTEK] HASH_TABLE_DEPTH is limitted %d.\n",NSTEK_DEPTH);
        return 0;
    }

    if(hash_table[depth][hash_index].used != 0)
    {
        if(nstek_compare_session(tuple, hash_table[depth][hash_index].tuple))
        {
            hash_table[depth][hash_index].used += 1;
            nstek_traffic_distributor(depth, hash_index, traffic);
        }
        else
        {
            hash_index = nstek_packet_to_session(tuple, traffic, depth + 1);
            if(hash_index == 0)
                return 0;
        }
    }
    else
    {
        hash_table[depth][hash_index].used = 1;
        nstek_tuple_distributor(depth, hash_index, tuple);
        nstek_traffic_distributor(depth, hash_index, traffic);
    }
    
    return hash_index;
}

static void
nstek_hash_table_init()
{
    int depth;

    hash_table = (HashTables**)malloc(NSTEK_DEPTH * sizeof(HashTables));
    if(hash_table == NULL)
    {
        printf("[NSTEK ERROR] %d_DEPTH_HASH_TABLE Memory allocation failed.\n", NSTEK_DEPTH);
        exit(1);
    }
    else
    {
        printf("[NSTEK] %d_DEPTH_HASH_TABLE Memory allocation successful.\n", NSTEK_DEPTH);
    }

    for(depth = 0; depth < NSTEK_DEPTH; depth++)
    {
        hash_table[depth] = (HashTables*)malloc(NSTEK_DEPTH_LN_CH(depth) * sizeof(HashTables));
        if(hash_table[depth] == NULL)
        {
            printf("[NSTEK ERROR] DEPTH_%.2d [%.8d] %.3d MB Memory allocation failed.\n", depth + 1, NSTEK_DEPTH_LN_CH(depth), (sizeof(hash_table[depth][NSTEK_DEPTH_LN_CH(depth)]) * NSTEK_DEPTH_LN_CH(depth) / NSTEK_BYTE_TO_MB));
            exit(1);
        }
        else
        {
            printf("[NSTEK] DEPTH_%.2d [%.8d] %.3d MB Memory allocation successful.\n", depth + 1, NSTEK_DEPTH_LN_CH(depth), (sizeof(hash_table[depth][NSTEK_DEPTH_LN_CH(depth)]) * NSTEK_DEPTH_LN_CH(depth) / NSTEK_BYTE_TO_MB));
        }
    }
}

static void
nstek_hash_table_free()
{
    int depth;

    for(depth = 0; depth < NSTEK_DEPTH; depth++)
    {
        free(hash_table[depth]);
        printf("[NSTEK] DEPTH_%.2d [%.8d] %.3d MB Memory deallocation successful.\n", depth + 1, NSTEK_DEPTH_LN_CH(depth), (sizeof(hash_table[depth][NSTEK_DEPTH_LN_CH(depth)]) * NSTEK_DEPTH_LN_CH(depth) / NSTEK_BYTE_TO_MB));
    }

    free(hash_table);
    printf("[NSTEK] %d_DEPTH_HASH_TABLE Memory deallocation successful.\n", NSTEK_DEPTH);
}

int main(void)
{
    int hash_index = 0;

    nstek_hash_table_init();

    Tuples tuple1 = {16843009, 16843010, 1024, 1025, 6};
    Traffics traffic = {4, 4, 4};

    hash_index = nstek_packet_to_session(tuple1, traffic, NSTEK_DEPTH_01);
    printf(
        "%d\t%u\t%u\t%u\t%u\t%u\t%u\t%u\n",
        hash_table[NSTEK_DEPTH_01][hash_index].tuple.src_addr,
        hash_table[NSTEK_DEPTH_01][hash_index].tuple.dst_addr,
        hash_table[NSTEK_DEPTH_01][hash_index].tuple.src_port,
        hash_table[NSTEK_DEPTH_01][hash_index].tuple.dst_port,
        hash_table[NSTEK_DEPTH_01][hash_index].tuple.protocol,
        hash_table[NSTEK_DEPTH_01][hash_index].traffic.tx,
        hash_table[NSTEK_DEPTH_01][hash_index].traffic.rx,
        hash_table[NSTEK_DEPTH_01][hash_index].traffic.dr
    );
    hash_index = nstek_packet_to_session(tuple1, traffic, NSTEK_DEPTH_01);
    printf(
        "%d\t%u\t%u\t%u\t%u\t%u\t%u\t%u\n",
        hash_table[NSTEK_DEPTH_01][hash_index].tuple.src_addr,
        hash_table[NSTEK_DEPTH_01][hash_index].tuple.dst_addr,
        hash_table[NSTEK_DEPTH_01][hash_index].tuple.src_port,
        hash_table[NSTEK_DEPTH_01][hash_index].tuple.dst_port,
        hash_table[NSTEK_DEPTH_01][hash_index].tuple.protocol,
        hash_table[NSTEK_DEPTH_01][hash_index].traffic.tx,
        hash_table[NSTEK_DEPTH_01][hash_index].traffic.rx,
        hash_table[NSTEK_DEPTH_01][hash_index].traffic.dr
    );

    nstek_hash_table_free();
}