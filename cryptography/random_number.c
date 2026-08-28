#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(int argc, char **argv) {
    srand(time(NULL));

    int r = rand();
    printf("r: %d\n", r);

    return 0;
}