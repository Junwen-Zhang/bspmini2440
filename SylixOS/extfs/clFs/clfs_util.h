/*
 * clfs utility functions
 *
 * Copyright (c) 2022, The clfs authors.
 * Copyright (c) 2017, Arm Limited. All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef CLFS_UTIL_H
#define CLFS_UTIL_H

// Users can override clfs_util.h with their own configuration by defining
// CLFS_CONFIG as a header file to include (-DCLFS_CONFIG=clfs_config.h).
//
// If CLFS_CONFIG is used, none of the default utils will be emitted and must be
// provided by the config file. To start, I would suggest copying clfs_util.h
// and modifying as needed.
#ifdef CLFS_CONFIG
#define CLFS_STRINGIZE(x) CLFS_STRINGIZE2(x)
#define CLFS_STRINGIZE2(x) #x
#include CLFS_STRINGIZE(CLFS_CONFIG)
#else

// System includes
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <inttypes.h>

#ifndef CLFS_NO_MALLOC
#include <stdlib.h>
#endif
#ifndef CLFS_NO_ASSERT
#include <assert.h>
#endif
#if !defined(CLFS_NO_DEBUG) || \
        !defined(CLFS_NO_WARN) || \
        !defined(CLFS_NO_ERROR) || \
        defined(CLFS_YES_TRACE)
#include <stdio.h>
#endif

#ifdef __cplusplus
extern "C"
{
#endif


// Macros, may be replaced by system specific wrappers. Arguments to these
// macros must not have side-effects as the macros can be removed for a smaller
// code footprint

// Logging functions
#ifndef CLFS_TRACE
#ifdef CLFS_YES_TRACE
#define CLFS_TRACE_(fmt, ...) \
    printf("%s:%d:trace: " fmt "%s\n", __FILE__, __LINE__, __VA_ARGS__)
#define CLFS_TRACE(...) CLFS_TRACE_(__VA_ARGS__, "")
#else
#define CLFS_TRACE(...)
#endif
#endif

#ifndef CLFS_DEBUG
#ifndef CLFS_NO_DEBUG
#define CLFS_DEBUG_(fmt, ...) \
    printf("%s:%d:debug: " fmt "%s\n", __FILE__, __LINE__, __VA_ARGS__)
#define CLFS_DEBUG(...) CLFS_DEBUG_(__VA_ARGS__, "")
#else
#define CLFS_DEBUG(...)
#endif
#endif

#ifndef CLFS_WARN
#ifndef CLFS_NO_WARN
#define CLFS_WARN_(fmt, ...) \
    printf("%s:%d:warn: " fmt "%s\n", __FILE__, __LINE__, __VA_ARGS__)
#define CLFS_WARN(...) CLFS_WARN_(__VA_ARGS__, "")
#else
#define CLFS_WARN(...)
#endif
#endif

#ifndef CLFS_ERROR
#ifndef CLFS_NO_ERROR
#define CLFS_ERROR_(fmt, ...) \
    printf("%s:%d:error: " fmt "%s\n", __FILE__, __LINE__, __VA_ARGS__)
#define CLFS_ERROR(...) CLFS_ERROR_(__VA_ARGS__, "")
#else
#define CLFS_ERROR(...)
#endif
#endif

// Runtime assertions
#ifndef CLFS_ASSERT
#ifndef CLFS_NO_ASSERT
#define CLFS_ASSERT(test) assert(test)
#else
#define CLFS_ASSERT(test)
#endif
#endif


// Builtin functions, these may be replaced by more efficient
// toolchain-specific implementations. CLFS_NO_INTRINSICS falls back to a more
// expensive basic C implementation for debugging purposes

// Min/max functions for unsigned 32-bit numbers
static inline uint32_t clfs_max(uint32_t a, uint32_t b) {
    return (a > b) ? a : b;
}

static inline uint32_t clfs_min(uint32_t a, uint32_t b) {
    return (a < b) ? a : b;
}

// Align to nearest multiple of a size
static inline uint32_t clfs_aligndown(uint32_t a, uint32_t alignment) {
    return a - (a % alignment);
}

static inline uint32_t clfs_alignup(uint32_t a, uint32_t alignment) {
    return clfs_aligndown(a + alignment-1, alignment);
}

// Find the smallest power of 2 greater than or equal to a
static inline uint32_t clfs_npw2(uint32_t a) {
#if !defined(CLFS_NO_INTRINSICS) && (defined(__GNUC__) || defined(__CC_ARM))
    return 32 - __builtin_clz(a-1);
#else
    uint32_t r = 0;
    uint32_t s;
    a -= 1;
    s = (a > 0xffff) << 4; a >>= s; r |= s;
    s = (a > 0xff  ) << 3; a >>= s; r |= s;
    s = (a > 0xf   ) << 2; a >>= s; r |= s;
    s = (a > 0x3   ) << 1; a >>= s; r |= s;
    return (r | (a >> 1)) + 1;
#endif
}

// Count the number of trailing binary zeros in a
// clfs_ctz(0) may be undefined
static inline uint32_t clfs_ctz(uint32_t a) {
#if !defined(CLFS_NO_INTRINSICS) && defined(__GNUC__)
    return __builtin_ctz(a);
#else
    return clfs_npw2((a & -a) + 1) - 1;
#endif
}

// Count the number of binary ones in a
static inline uint32_t clfs_popc(uint32_t a) {
#if !defined(CLFS_NO_INTRINSICS) && (defined(__GNUC__) || defined(__CC_ARM))
    return __builtin_popcount(a);
#else
    a = a - ((a >> 1) & 0x55555555);
    a = (a & 0x33333333) + ((a >> 2) & 0x33333333);
    return (((a + (a >> 4)) & 0xf0f0f0f) * 0x1010101) >> 24;
#endif
}

// Find the sequence comparison of a and b, this is the distance
// between a and b ignoring overflow
static inline int clfs_scmp(uint32_t a, uint32_t b) {
    return (int)(unsigned)(a - b);
}

// Convert between 32-bit little-endian and native order
static inline uint32_t clfs_fromle32(uint32_t a) {
#if !defined(CLFS_NO_INTRINSICS) && ( \
    (defined(  BYTE_ORDER  ) && defined(  ORDER_LITTLE_ENDIAN  ) &&   BYTE_ORDER   ==   ORDER_LITTLE_ENDIAN  ) || \
    (defined(__BYTE_ORDER  ) && defined(__ORDER_LITTLE_ENDIAN  ) && __BYTE_ORDER   == __ORDER_LITTLE_ENDIAN  ) || \
    (defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__))
    return a;
#elif !defined(CLFS_NO_INTRINSICS) && ( \
    (defined(  BYTE_ORDER  ) && defined(  ORDER_BIG_ENDIAN  ) &&   BYTE_ORDER   ==   ORDER_BIG_ENDIAN  ) || \
    (defined(__BYTE_ORDER  ) && defined(__ORDER_BIG_ENDIAN  ) && __BYTE_ORDER   == __ORDER_BIG_ENDIAN  ) || \
    (defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__))
    return __builtin_bswap32(a);
#else
    return (((uint8_t*)&a)[0] <<  0) |
           (((uint8_t*)&a)[1] <<  8) |
           (((uint8_t*)&a)[2] << 16) |
           (((uint8_t*)&a)[3] << 24);
#endif
}

static inline uint32_t clfs_tole32(uint32_t a) {
    return clfs_fromle32(a);
}

// Convert between 32-bit big-endian and native order
static inline uint32_t clfs_frombe32(uint32_t a) {
#if !defined(CLFS_NO_INTRINSICS) && ( \
    (defined(  BYTE_ORDER  ) && defined(  ORDER_LITTLE_ENDIAN  ) &&   BYTE_ORDER   ==   ORDER_LITTLE_ENDIAN  ) || \
    (defined(__BYTE_ORDER  ) && defined(__ORDER_LITTLE_ENDIAN  ) && __BYTE_ORDER   == __ORDER_LITTLE_ENDIAN  ) || \
    (defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__))
    return __builtin_bswap32(a);
#elif !defined(CLFS_NO_INTRINSICS) && ( \
    (defined(  BYTE_ORDER  ) && defined(  ORDER_BIG_ENDIAN  ) &&   BYTE_ORDER   ==   ORDER_BIG_ENDIAN  ) || \
    (defined(__BYTE_ORDER  ) && defined(__ORDER_BIG_ENDIAN  ) && __BYTE_ORDER   == __ORDER_BIG_ENDIAN  ) || \
    (defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__))
    return a;
#else
    return (((uint8_t*)&a)[0] << 24) |
           (((uint8_t*)&a)[1] << 16) |
           (((uint8_t*)&a)[2] <<  8) |
           (((uint8_t*)&a)[3] <<  0);
#endif
}

static inline uint32_t clfs_tobe32(uint32_t a) {
    return clfs_frombe32(a);
}

// Calculate CRC-32 with polynomial = 0x04c11db7
uint32_t clfs_crc(uint32_t crc, const void *buffer, size_t size);

// Allocate memory, only used if buffers are not provided to clfs
// Note, memory must be 64-bit aligned
static inline void *clfs_malloc(size_t size) {
#ifndef CLFS_NO_MALLOC
    return malloc(size);
#else
    (void)size;
    return NULL;
#endif
}

// Deallocate memory, only used if buffers are not provided to clfs
static inline void clfs_free(void *p) {
#ifndef CLFS_NO_MALLOC
    free(p);
#else
    (void)p;
#endif
}


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
#endif
