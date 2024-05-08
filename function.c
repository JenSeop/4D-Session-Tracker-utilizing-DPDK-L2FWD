#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define NSTEK_DEPTH 4
#define NSTEK_DEPTH_01 0
#define NSTEK_DEPTH_02 1
#define NSTEK_DEPTH_03 2
#define NSTEK_DEPTH_04 3

#define NSTEK_DEPTH_01_LN 16777216
#define NSTEK_DEPTH_02_LN 8388608
#define NSTEK_DEPTH_03_LN 4194304
#define NSTEK_DEPTH_04_LN 2097152

#define NSTEK_DEPTH_01_DR 16777213
#define NSTEK_DEPTH_02_DR 8388593
#define NSTEK_DEPTH_03_DR 4194301
#define NSTEK_DEPTH_04_DR 2097143

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

uint32_t NSTEK_DEPTH_01_CNT = 0;
uint32_t NSTEK_DEPTH_02_CNT = 0;
uint32_t NSTEK_DEPTH_03_CNT = 0;
uint32_t NSTEK_DEPTH_04_CNT = 0;

uint32_t NSTEK_DEPTH_01_AVG = 0;
uint32_t NSTEK_DEPTH_02_AVG = 0;
uint32_t NSTEK_DEPTH_03_AVG = 0;
uint32_t NSTEK_DEPTH_04_AVG = 0;

uint32_t NSTEK_DEPTH_01_DIF = 0;
uint32_t NSTEK_DEPTH_02_DIF = 0;
uint32_t NSTEK_DEPTH_03_DIF = 0;
uint32_t NSTEK_DEPTH_04_DIF = 0;

int idx;

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

    240502 - 652M - 4D - 0.0026605151864667435
    240503 - 942M - 4D - 0.028827108936881042
*/

static uint32_t
nstek_hash(Tuples tuple, int depth, uint32_t brace)
{
    uint32_t hash = (NSTEK_DEPTH_DR_CH(depth) >> brace);
    
    hash ^= ((tuple.src_addr >> 16) + (tuple.dst_addr & 0xFFFF)) >> (~depth + tuple.protocol);
    hash ^= (tuple.src_addr & 0xFFFF) ^ (tuple.dst_addr >> 16) >> (~depth + tuple.protocol);
    hash ^= ((tuple.src_port >> 8) + (tuple.dst_port & 0xFF)) >> (~depth + tuple.protocol);
    hash ^= (tuple.src_port & 0xFF) ^ (tuple.dst_port >> 8) >> (~depth + tuple.protocol);
    hash = hash & (NSTEK_DEPTH_LN_CH(depth) - 1);
    
    return hash;
}

static uint32_t
nstek_hash_mul(Tuples tuple, int depth, uint32_t brace)
{
    uint32_t hash = NSTEK_DEPTH_DR_CH(depth);
    
    hash = (~hash * ~(tuple.src_addr * tuple.dst_addr)) >> (~depth + tuple.protocol);
    hash = (~hash * ~(~tuple.src_port * ~tuple.dst_port)) >> (~depth + tuple.protocol);
    hash = (hash >> brace) % NSTEK_DEPTH_LN_CH(depth);

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

static void
nstek_depth_diff_calculator(int depth, uint32_t hash_index)
{
    switch(depth)
    {
        case NSTEK_DEPTH_01:
            NSTEK_DEPTH_01_CNT += 1;
            NSTEK_DEPTH_01_AVG = (NSTEK_DEPTH_01_AVG + hash_index) / 2;
            break;
        case NSTEK_DEPTH_02:
            NSTEK_DEPTH_02_CNT += 1;
            NSTEK_DEPTH_02_AVG = (NSTEK_DEPTH_02_AVG + hash_index) / 2;
            break;
        case NSTEK_DEPTH_03:
            NSTEK_DEPTH_03_CNT += 1;
            NSTEK_DEPTH_03_AVG = (NSTEK_DEPTH_03_AVG + hash_index) / 2;
            break;
        case NSTEK_DEPTH_04:
            NSTEK_DEPTH_04_CNT += 1;
            NSTEK_DEPTH_04_AVG = (NSTEK_DEPTH_04_AVG + hash_index) / 2;
            break;
    }
}

static int
nstek_packet_to_session(Tuples tuple, Traffics traffic, int depth, uint32_t brace)
{
    uint32_t hash_index = nstek_hash(tuple, depth, brace);

    if(hash_table[depth][hash_index].used != 0)
    {
        if(nstek_compare_session(tuple, hash_table[depth][hash_index].tuple))
        {
            hash_table[depth][hash_index].used += 1;
            nstek_traffic_distributor(depth, hash_index, traffic);
            return hash_index;
        }
        else
        {
            printf("COL HASH = %u DEPTH = %d BRACE = %u\n",hash_index,depth,brace);
            if(depth < NSTEK_DEPTH)
            {
                hash_index = nstek_packet_to_session(tuple, traffic, depth + 1, brace);
            }
            else
            {
                printf("BRACE!!\n");
                hash_index = nstek_packet_to_session(tuple, traffic, NSTEK_DEPTH_01, brace + 1);
            }
        }
    }
    else if(hash_table[depth][hash_index].used == 0)
    {
        hash_table[depth][hash_index].used = 1;
        nstek_tuple_distributor(depth, hash_index, tuple);
        nstek_traffic_distributor(depth, hash_index, traffic);
        nstek_depth_diff_calculator(depth, hash_index);
    }

    return hash_index;
}

static void
nstek_session_display()
{
    uint32_t hash_index;
    int depth;

    for(depth = 0; depth < NSTEK_DEPTH; depth++)
    {
        for(hash_index = 0; hash_index < NSTEK_DEPTH_LN_CH(depth); hash_index++)
        {
            if(hash_table[depth][hash_index].used)
            {
                printf(
                    "D-%d\t%d\t\t%.3d.%.3d.%.3d.%.3d\t\t%.3d.%.3d.%.3d.%.3d\t\t%d\t%d\t%s\t\t%u\t%u\t%u\n",
                    // Depth
                    depth + 1,
                    // Hash Table
                    hash_index,
                    // SRC IP
                    (hash_table[depth][hash_index].tuple.src_addr>>0) & 0XFF,
                    (hash_table[depth][hash_index].tuple.src_addr>>8) & 0XFF,
                    (hash_table[depth][hash_index].tuple.src_addr>>16) & 0XFF,
                    (hash_table[depth][hash_index].tuple.src_addr>>24) & 0XFF,
                    // DST IP
                    (hash_table[depth][hash_index].tuple.dst_addr>>0) & 0XFF,
                    (hash_table[depth][hash_index].tuple.dst_addr>>8) & 0XFF,
                    (hash_table[depth][hash_index].tuple.dst_addr>>16) & 0XFF,
                    (hash_table[depth][hash_index].tuple.dst_addr>>24) & 0XFF,
                    // SRC PORT
                    NSTEK_REV_ENDIAN(hash_table[depth][hash_index].tuple.src_port),
                    // DST PORT
                    NSTEK_REV_ENDIAN(hash_table[depth][hash_index].tuple.dst_port),
                    // PROTOCOL
                    NSTEK_PROTOCOL((hash_table[depth][hash_index].tuple.protocol)),
                    // TX
                    hash_table[depth][hash_index].traffic.tx,
                    // RX
                    hash_table[depth][hash_index].traffic.rx,
                    // DR
                    hash_table[depth][hash_index].traffic.dr
                );
            }
        }
    }
    printf(
        "\n[Depth Capacity]\t(D-1) %u\t(D-2) %u\t(D-3) %u\t(D-4) %u",
        NSTEK_DEPTH_01_CNT,
        NSTEK_DEPTH_02_CNT,
        NSTEK_DEPTH_03_CNT,
        NSTEK_DEPTH_04_CNT
    );
    printf(
        "\n[Depth Load factor]\t(D-1) %f\t(D-2) %f\t(D-3) %f\t(D-4) %f",
        (float) NSTEK_DEPTH_01_CNT / (float) NSTEK_DEPTH_01_LN * 100,
        (float) NSTEK_DEPTH_02_CNT / (float) NSTEK_DEPTH_02_LN * 100,
        (float) NSTEK_DEPTH_03_CNT / (float) NSTEK_DEPTH_03_LN * 100,
        (float) NSTEK_DEPTH_04_CNT / (float) NSTEK_DEPTH_04_LN * 100
    );
    printf(
        "\n[Depth Hash AVG]\t(D-1) %u\t(D-2) %u\t(D-3) %u\t(D-4) %u",
        NSTEK_DEPTH_01_AVG,
        NSTEK_DEPTH_02_AVG,
        NSTEK_DEPTH_03_AVG,
        NSTEK_DEPTH_04_AVG
    );
    printf("\n\n");
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
    nstek_hash_table_init();

    for(idx = 0; idx < 255 * 255; idx++)
    {
        Tuples tuple1 = {16843009 + idx, 16843009 + idx, 1024, 1025, 6};
        Traffics traffic1 = {4, 4, 4};
        printf("%u\n",nstek_packet_to_session(tuple1, traffic1, NSTEK_DEPTH_01, 0));
    }

    nstek_session_display();
    
    nstek_hash_table_free();
}