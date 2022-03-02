#ifndef CACHE_H
#define CACHE_H


/*=============================================================================
L1-ICache parameters
            smallBoomConfig	          megaBoomConfig
Fetch bytes	        8	                      16
Block bytes         64	                      64
Row bytes	        8	                      16
Word bits	        64	                      128
Sets	            64	                      64
Ways	            4	                      8
Refill cycles	    8	                      4
RAMs	     (64 x 512) using 1 banks	(64 x 256)  using 2 banks
I-TLB entries	32	32
================================================================================*/

// cache values
// TODO: check that these parameters are right

// cache line size, cache line是cache和主存之间数据传输的最小单位;
// 例如一个64 Bytes大小的cache, 我们可以利用地址低 6 bits来寻址64 bytes中某一字节，我们称这部分bit组合为offset;
#define L1_BLOCK_SZ_BYTES 64
#define L1_BLOCK_BITS 6 // note: this is log2Ceil(L1_BLOCK_SZ_BYTES)

// 64行cache line，为了覆盖所有行。我们需要6 bits（如上图地址黄色部分）查找某一行，这部分地址部分称之为set index (Idx)
#define L1_SETS 64
#define L1_SET_BITS 6 // note: this is log2Ceil(L1_SETS)

// 什么是路（way）的概念。我们将cache平均分成多份，每一份就是一路。因此，4路组相连缓存就是将cache平均分成4份
// #define L1_WAYS 8 //note: this looks like there are 8 ways
#define L1_WAYS 4 //note: this looks like there are 4 ways for small boom

#define L1_SZ_BYTES (L1_SETS*L1_WAYS*L1_BLOCK_SZ_BYTES)    // cahe size，代表cache可以缓存最大数据的大小

#define FULL_MASK 0xFFFFFFFFFFFFFFFF
// tag中保存的是整个地址位宽去除index和offset使用的bit剩余部分
#define TAG_MASK (FULL_MASK << (L1_SET_BITS + L1_BLOCK_BITS))
// offset mask
#define OFF_MASK (~(FULL_MASK << L1_BLOCK_BITS))
// cache line (set) mask
#define SET_MASK (~(TAG_MASK | OFF_MASK))

/* ----------------------------------
 * |                  Cache address |
 * ----------------------------------
 * |       tag |      idx |  offset |
 * ----------------------------------
 * | 63 <-> 12 | 11 <-> 6 | 5 <-> 0 |
 * ----------------------------------
 */

// setup array size of cache to "put" in the cache on $ flush
// guarantees contiguous set of addrs that is at least the sz of cache
// 5 so that you can hit more
uint8_t dummyMem[5 * L1_SZ_BYTES];

/**
 * Flush the cache of the address given since RV64 does not have a
 * clflush type of instruction. Clears any set that has the same idx bits
 * as the address input range.
 *
 * Note: This does not work if you are trying to flush dummyMem out of the
 * cache.
 *
 * @param addr starting address to clear the cache
 * @param sz size of the data to remove in bytes
 */
void flushCache(uint64_t addr, uint64_t sz)
{
    // printf("Flushed addr(0x%lx) tag(0x%lx) set(0x%lx) off(0x%lx) sz(%ld)\n", addr, (addr & TAG_MASK) >> (L1_SET_BITS + L1_BLOCK_BITS), 
    //                                                                    (addr & SET_MASK) >> L1_BLOCK_BITS, addr & OFF_MASK, sz);

    // find out the amount of blocks you want to clear
    uint64_t numSetsClear = sz >> L1_BLOCK_BITS;
    if ((sz & OFF_MASK) != 0)
    {
        numSetsClear += 1;
    }

    if (numSetsClear > L1_SETS)
    {
        // flush entire cache with no rollover (makes the function finish faster) 
        numSetsClear = L1_SETS;
    }
    
    //printf("numSetsClear(%ld)\n", numSetsClear);

    // temp variable used for nothing
    uint8_t dummy = 0;

    // this mem address is the start of a contiguous set of memory that will fit inside of the cache
    // thus it has the following properties
    // 1. dummyMem <= alignedMem < dummyMem + sizeof(dummyMem)
    // 2. alignedMem has idx = 0 and offset = 0 
    uint64_t alignedMem = (((uint64_t)dummyMem) + L1_SZ_BYTES) & TAG_MASK;
    //printf("alignedMem(0x%lx)\n", alignedMem);
        
    for (uint64_t i = 0; i < numSetsClear; ++i)
    {
        // offset to move across the sets that you want to flush
        uint64_t setOffset = (((addr & SET_MASK) >> L1_BLOCK_BITS) + i) << L1_BLOCK_BITS;
        //printf("setOffset(0x%lx)\n", setOffset);

        // since there are L1_WAYS you need to flush the entire set
        for(uint64_t j = 0; j < 4*L1_WAYS; ++j)   //j < 4*L1_WAYS
        {
            // offset to reaccess the set
            uint64_t wayOffset = j << (L1_BLOCK_BITS + L1_SET_BITS);
            //printf("wayOffset(0x%lx)\n", wayOffset);

            // evict the previous cache block and put in the dummy mem
            dummy = *((uint8_t*)(alignedMem + setOffset + wayOffset));
            //printf("evict read(0x%lx)\n", alignedMem + setOffset + wayOffset);
        }
    }
}

#endif
