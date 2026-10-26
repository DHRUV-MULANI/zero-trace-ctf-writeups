#include <stdio.h>
#include <stdint.h>

static const uint64_t A = 6364136223846793005ULL;
static const uint64_t C = 1442695040888963407ULL;

static inline uint64_t nx(uint64_t s){ return A*s + C; }

int main(void){
    /* top 32 bits observed, oldest first */
    uint32_t t[10] = {
        0x32a38bf3u, 0xb67f750au, 0xb658d79au, 0x0c1f3bf4u, 0xd4b95a26u,
        0xa4bd019eu, 0xf0759990u, 0xfd8be8bfu, 0xe3b17eeau, 0xb7bb3059u
    };
    uint64_t found = 0;
    for(uint64_t lo=0; lo<(1ULL<<32); lo++){
        uint64_t s = ((uint64_t)t[0]<<32) | lo;
        uint64_t cur = s;
        int ok = 1;
        for(int i=1;i<10;i++){
            cur = nx(cur);
            if((uint32_t)(cur>>32) != t[i]){ ok=0; break; }
        }
        if(ok){
            found++;
            printf("MATCH lo=%llu state0=0x%016llx next=0x%016llx next_dec=%llu\n",
                   (unsigned long long)lo,
                   (unsigned long long)s,
                   (unsigned long long)nx(cur),
                   (unsigned long long)nx(cur));
        }
    }
    printf("total matches: %llu\n",(unsigned long long)found);
    return 0;
}
