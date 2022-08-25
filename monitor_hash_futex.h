#ifndef __MONITOR_HASH_FUTEX_H
#define __MONITOR_HASH_FUTEX_H

#ifndef CMD_LEN
#define CMD_LEN 16
#endif

#ifndef PATH_LEN
#define PATH_LEN 128
#endif

struct data_t {
    __u32 pid;
    char comm[CMD_LEN];
    __u32 hash;
    __u32 hash_size;
};

/*
 * Following hash alogrithm is copied from implementation in Linux header file:
 * include/linux/jhash.h
 */

#ifndef u32
#define u32 unsigned int
#endif

/* An arbitrary initial parameter */
#define JHASH_INITVAL       0xdeadbeef

/**
 * rol32 - rotate a 32-bit value left
 * @word: value to rotate
 * @shift: bits to roll
 */
static inline __u32 rol32(__u32 word, unsigned int shift)
{
    return (word << (shift & 31)) | (word >> ((-shift) & 31));
}

/* __jhash_mix -- mix 3 32-bit values reversibly. */
#define __jhash_mix(a, b, c)            \
{                       \
    a -= c;  a ^= rol32(c, 4);  c += b; \
    b -= a;  b ^= rol32(a, 6);  a += c; \
    c -= b;  c ^= rol32(b, 8);  b += a; \
    a -= c;  a ^= rol32(c, 16); c += b; \
    b -= a;  b ^= rol32(a, 19); a += c; \
    c -= b;  c ^= rol32(b, 4);  b += a; \
}

/* __jhash_final - final mixing of 3 32-bit values (a,b,c) into c */
#define __jhash_final(a, b, c)          \
{                       \
    c ^= b; c -= rol32(b, 14);      \
    a ^= c; a -= rol32(c, 11);      \
    b ^= a; b -= rol32(a, 25);      \
    c ^= b; c -= rol32(b, 16);      \
    a ^= c; a -= rol32(c, 4);       \
    b ^= a; b -= rol32(a, 14);      \
    c ^= b; c -= rol32(b, 24);      \
}


/**
 * fls - find last (most-significant) bit set
 * @x: the word to search
 *
 * This is defined the same way as ffs.
 * Note fls(0) = 0, fls(1) = 1, fls(0x80000000) = 32.
 */
static __always_inline int fls(__u32 x)
{
    return x ? sizeof(x) * 8 - __builtin_clz(x) : 0;
}

/**
 * roundup_pow_of_two - round the given value up to nearest power of two
 * @n: parameter
 *
 * round the given value up to the nearest power of two
 * - the result is undefined when n == 0
 * - this can be used to initialise global variables from constant data
 */
static inline __u32 roundup_pow_of_two(__u32 n)
{
    return 1UL << fls(n - 1);
}

#endif //__MONITOR_HASH_FUTEX_H
