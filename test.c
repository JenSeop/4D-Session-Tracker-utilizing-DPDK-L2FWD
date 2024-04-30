#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define STR_LEN 20000000

char *depth_01;
char *depth_02;

void depth_01_init()
{
    depth_01 = (char*)malloc(STR_LEN * sizeof(char));

    for(int idx = 0; idx < STR_LEN; idx++)
        depth_01[idx] = 'a';
    
    depth_01[STR_LEN] = '\0';
    
    printf("depth_01_init = %d\n",strlen(depth_01));
}

void depth_01_free()
{
    free(depth_01);
    printf("depth_01_free\n");
}

void depth_02_init()
{
    depth_02 = (char*)malloc((STR_LEN / 2) * sizeof(char));

    for(int idx = 0; idx < (STR_LEN / 2); idx++)
        depth_02[idx] = 'a';

    depth_02[STR_LEN / 2] = '\0';
    
    printf("depth_02_init = %d\n",strlen(depth_02));
}

void depth_02_free()
{
    free(depth_02);
    printf("depth_02_free\n");
}

int main(void)
{
    // INIT
    depth_01_init();
    depth_02_init();
    // FREE
    depth_01_free();
    depth_02_free();

    return 0;
}