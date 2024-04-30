#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define STR_LEN 20000000

int main(void)
{
    char *str1 = (char*)malloc(STR_LEN * sizeof(char));
    char *str2 = (char*)malloc((STR_LEN / 6) * sizeof(char));

    for(int idx = 0; idx < STR_LEN; idx++)
    {
        str1[idx] = 'a';
        str2[idx] = 'a';
    }
    str1[STR_LEN] = '\0';
    str2[STR_LEN / 10] = '\0';

    printf("strlen1 = %d\n",strlen(str1));
    free(str1);
    printf("strlen2 = %d\n",strlen(str2));
    free(str2);
}