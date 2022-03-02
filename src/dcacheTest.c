#include <stdio.h>
#include <stdint.h> 
#include "encoding.h"
#include "cache.h"

#define SET_IDX  4   //This is critical, SET_IDX =2,3, sometimes it does not work; but SET_IDX =4 is ok
uint8_t array2[256 * L1_BLOCK_SZ_BYTES]={0};
int j=0;

int main(void)
{
    uint8_t    dummy = 0;
    uint64_t   start=0, diff=0;
    printf("================= data cache test ========================= \n");

    //flush the above element from data cache then read from RAM
    for(int i=0; i<5; i++)
    {  
        // make sure the array you read from is not in the cache
        flushCache((uint64_t)array2, sizeof(array2));
        
        //read from the RAM        
        start = rdcycle();
        dummy = array2[0 * L1_BLOCK_SZ_BYTES];
        diff = (rdcycle() - start);
        printf("iteration=%d, read from ram, cycles = %lu\n", i, diff);   

        //preload the data into data cache
        dummy = array2[SET_IDX*L1_BLOCK_SZ_BYTES];

        //read from data cache
        start = rdcycle();
        dummy = array2[SET_IDX * L1_BLOCK_SZ_BYTES];
        diff = (rdcycle() - start);
        printf("iteration=%d, read from data cache, cycles = %lu\n", i, diff);   

        //read from ram after flush
        uint64_t addr = (uint64_t)array2 + SET_IDX * L1_BLOCK_SZ_BYTES;
        //printf("flush the addr:0x%lx , array2 =0x%lx\n", addr, (uint64_t)array2);
        flushCache(addr, sizeof(uint8_t));
        //read from cache after flush
        start = rdcycle();
        dummy = array2[SET_IDX * L1_BLOCK_SZ_BYTES];
        diff = (rdcycle() - start);
        printf("iteration=%d, flush and then read from ram, cycles = %lu\n", i, diff); 

        //read from cache after flush
        start = rdcycle();
        dummy = array2[SET_IDX * L1_BLOCK_SZ_BYTES];
        diff = (rdcycle() - start);
        printf("iteration=%d, read from data cache after flush, cycles = %lu\n\n", i, diff);          
    }
    return 0;
}


/*
shawnliu@shawnliu-Aspire-TC-780:/media/shawnliu/AI_DISK/sonicboom/chipyard/sims/verilator$ ./simulator-chipyard-SmallBoomConfig dcacheTest.riscv 
This emulator compiled with JTAG Remote Bitbang client. To enable, use +jtag_rbb_enable=1.
Listening on port 42005
[UART] UART0 is here (stdin/stdout).
================= data cache test ========================= 
iteration=0, read from ram, cycles = 70
iteration=0, read from data cache, cycles = 40
iteration=0, flush and then read from ram, cycles = 62
iteration=0, read from data cache after flush, cycles = 39

iteration=1, read from ram, cycles = 72
iteration=1, read from data cache, cycles = 40
iteration=1, flush and then read from ram, cycles = 62
iteration=1, read from data cache after flush, cycles = 39

iteration=2, read from ram, cycles = 70
iteration=2, read from data cache, cycles = 40
iteration=2, flush and then read from ram, cycles = 62
iteration=2, read from data cache after flush, cycles = 39

iteration=3, read from ram, cycles = 70
iteration=3, read from data cache, cycles = 40
iteration=3, flush and then read from ram, cycles = 62
iteration=3, read from data cache after flush, cycles = 39

iteration=4, read from ram, cycles = 72
iteration=4, read from data cache, cycles = 40
iteration=4, flush and then read from ram, cycles = 62
iteration=4, read from data cache after flush, cycles = 39

*/