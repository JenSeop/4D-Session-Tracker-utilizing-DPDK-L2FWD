#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define DEPTH_LEN 20000000

char *depth_01;
char *depth_02;
char *depth_03;
char *depth_04;

void depth_init(char *depth, int sep)
{
    int len = DEPTH_LEN;
    for(int cnt = sep - 1; cnt; cnt--)
        len /= 2;

    depth = (char*)malloc(len * sizeof(char));

    for(int idx = 0; idx < len; idx++)
        depth[idx] = 'a';
    
    depth[len] = '\0';
    
    printf("depth_%.2d_init = %d\n",sep,strlen(depth));
}

void depth_free(char *depth, int sep)
{
    free(depth);
    printf("depth_%.2d_free\n",sep);
}

int main(void)
{
    // INIT
    depth_init(depth_01, 1);
    depth_init(depth_02, 2);
    depth_init(depth_03, 3);
    depth_init(depth_04, 4);
    // FREE
    depth_free(depth_01, 1);
    depth_free(depth_02, 2);
    depth_free(depth_03, 3);
    depth_free(depth_04, 4);

    return 0;
}