#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
int main(void) {
    void *a = malloc(0x500), *b = malloc(0x20);
    free(a);
    printf("fd=%p\n", *(void **)a);
    FILE *f = fopen("/proc/self/maps", "r");
    char line[256];
    while (fgets(line, sizeof line, f)) fputs(line, stdout);
    (void)b;
}
