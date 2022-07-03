/*********************************************************************************************************
**
**                                    中国软件开源组织
**
**                                   嵌入式实时操作系统
**
**                                     SylixOS(TM)
**
**                               Copyright All Rights Reserved
**
**--------------文件信息--------------------------------------------------------------------------------
**
** 文   件   名: cqufs_util.h
**
** 创   建   人: cqu Group
**
** 文件创建日期: 2022 年 06 月 04 日
**
** 描        述: cqufs相关工具包的h文件
*********************************************************************************************************/
#ifndef CQUFS_UTIL_H
#define CQUFS_UTIL_H
/*********************************************************************************************************
  说明：通过将CQUFS_CONFIG定义为要包含的头文件(-DCQUFS_CONFIG= CQUFS_CONFIG .h)，用户可以使用自己的配置来覆盖cqufs_util.h。如果使用了CQUFS_CONFIG，则不会发出任何默认的utils，并且必须由配置文件提供。建议复制cqufs_util.h并根据需要进行修改。
*********************************************************************************************************/
#ifdef CQUFS_CONFIG
#define CQUFS_STRINGIZE(x) CQUFS_STRINGIZE2(x)
#define CQUFS_STRINGIZE2(x) #x
#include CQUFS_STRINGIZE(CQUFS_CONFIG)
#else
/*********************************************************************************************************
  说明：系统包括
*********************************************************************************************************/
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <inttypes.h>

#ifndef CQUFS_NO_MALLOC
#include <stdlib.h>
#endif
#ifndef CQUFS_NO_ASSERT
#include <assert.h>
#endif
#if !defined(CQUFS_NO_DEBUG) || \
        !defined(CQUFS_NO_WARN) || \
        !defined(CQUFS_NO_ERROR) || \
        defined(CQUFS_YES_TRACE)
#include <stdio.h>
#endif

#ifdef __cplusplus
extern "C"
{
#endif

/*********************************************************************************************************
  说明：宏，可以由系统特定的包装器替换。这些宏的参数不能有副作用，因为可以删除这些宏以减少代码占用
*********************************************************************************************************/
/*********************************************************************************************************
  说明：日志记录功能
*********************************************************************************************************/
#ifndef CQUFS_TRACE
#ifdef CQUFS_YES_TRACE
#define CQUFS_TRACE_(fmt, ...) \
    printf("%s:%d:trace: " fmt "%s\n", __FILE__, __LINE__, __VA_ARGS__)
#define CQUFS_TRACE(...) CQUFS_TRACE_(__VA_ARGS__, "")
#else
#define CQUFS_TRACE(...)
#endif
#endif

#ifndef CQUFS_DEBUG
#ifndef CQUFS_NO_DEBUG
#define CQUFS_DEBUG_(fmt, ...) \
    printf("%s:%d:debug: " fmt "%s\n", __FILE__, __LINE__, __VA_ARGS__)
#define CQUFS_DEBUG(...) CQUFS_DEBUG_(__VA_ARGS__, "")
#else
#define CQUFS_DEBUG(...)
#endif
#endif

#ifndef CQUFS_WARN
#ifndef CQUFS_NO_WARN
#define CQUFS_WARN_(fmt, ...) \
    printf("%s:%d:warn: " fmt "%s\n", __FILE__, __LINE__, __VA_ARGS__)
#define CQUFS_WARN(...) CQUFS_WARN_(__VA_ARGS__, "")
#else
#define CQUFS_WARN(...)
#endif
#endif

#ifndef CQUFS_ERROR
#ifndef CQUFS_NO_ERROR
#define CQUFS_ERROR_(fmt, ...) \
    printf("%s:%d:error: " fmt "%s\n", __FILE__, __LINE__, __VA_ARGS__)
#define CQUFS_ERROR(...) CQUFS_ERROR_(__VA_ARGS__, "")
#else
#define CQUFS_ERROR(...)
#endif
#endif

#ifndef CQUFS_ASSERT
#ifndef CQUFS_NO_ASSERT
#define CQUFS_ASSERT(test) assert(test)
#else
#define CQUFS_ASSERT(test)
#endif
#endif

/*********************************************************************************************************
  说明：内置函数，这些函数可能会被更高效的特定于工具链的实现所取代。CQUFS_NO_INTRINSICS为了调试的目的，采用了更昂贵的基本C实现,用于无符号32位数字的最小/最大函数
*********************************************************************************************************/
static inline uint32_t cqufs_max(uint32_t a, uint32_t b) {
    return (a > b) ? a : b;
}

static inline uint32_t cqufs_min(uint32_t a, uint32_t b) {
    return (a < b) ? a : b;
}
/*********************************************************************************************************
  说明：对齐到大小的最近倍数
*********************************************************************************************************/
static inline uint32_t cqufs_aligndown(uint32_t a, uint32_t alignment) {
    return a - (a % alignment);
}

static inline uint32_t cqufs_alignup(uint32_t a, uint32_t alignment) {
    return cqufs_aligndown(a + alignment-1, alignment);
}
/*********************************************************************************************************
  说明：求大于或等于a的2的最小幂
*********************************************************************************************************/
static inline uint32_t cqufs_npw2(uint32_t a) {
#if !defined(CQUFS_NO_INTRINSICS) && (defined(__GNUC__) || defined(__CC_ARM))
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
/*********************************************************************************************************
  说明：计数cqufs_ctz(0)中尾随二进制零的数量可能未定义
*********************************************************************************************************/
static inline uint32_t cqufs_ctz(uint32_t a) {
#if !defined(CQUFS_NO_INTRINSICS) && defined(__GNUC__)
    return __builtin_ctz(a);
#else
    return cqufs_npw2((a & -a) + 1) - 1;
#endif
}
/*********************************************************************************************************
  说明：计算a中二进制1的个数
*********************************************************************************************************/
static inline uint32_t cqufs_popc(uint32_t a) {
#if !defined(CQUFS_NO_INTRINSICS) && (defined(__GNUC__) || defined(__CC_ARM))
    return __builtin_popcount(a);
#else
    a = a - ((a >> 1) & 0x55555555);
    a = (a & 0x33333333) + ((a >> 2) & 0x33333333);
    return (((a + (a >> 4)) & 0xf0f0f0f) * 0x1010101) >> 24;
#endif
}
/*********************************************************************************************************
  说明：求a和b的序列比较，这是忽略溢出的a和b之间的距离
*********************************************************************************************************/
static inline int cqufs_scmp(uint32_t a, uint32_t b) {
    return (int)(unsigned)(a - b);
}
/*********************************************************************************************************
  说明：在32位小端顺序和本机顺序之间进行转换
*********************************************************************************************************/
static inline uint32_t cqufs_fromle32(uint32_t a) {
#if !defined(CQUFS_NO_INTRINSICS) && ( \
    (defined(  BYTE_ORDER  ) && defined(  ORDER_LITTLE_ENDIAN  ) &&   BYTE_ORDER   ==   ORDER_LITTLE_ENDIAN  ) || \
    (defined(__BYTE_ORDER  ) && defined(__ORDER_LITTLE_ENDIAN  ) && __BYTE_ORDER   == __ORDER_LITTLE_ENDIAN  ) || \
    (defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__))
    return a;
#elif !defined(CQUFS_NO_INTRINSICS) && ( \
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

static inline uint32_t cqufs_tole32(uint32_t a) {
    return cqufs_fromle32(a);
}
/*********************************************************************************************************
  说明：在32位大端顺序和本机顺序之间进行转换
*********************************************************************************************************/
static inline uint32_t cqufs_frombe32(uint32_t a) {
#if !defined(CQUFS_NO_INTRINSICS) && ( \
    (defined(  BYTE_ORDER  ) && defined(  ORDER_LITTLE_ENDIAN  ) &&   BYTE_ORDER   ==   ORDER_LITTLE_ENDIAN  ) || \
    (defined(__BYTE_ORDER  ) && defined(__ORDER_LITTLE_ENDIAN  ) && __BYTE_ORDER   == __ORDER_LITTLE_ENDIAN  ) || \
    (defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__))
    return __builtin_bswap32(a);
#elif !defined(CQUFS_NO_INTRINSICS) && ( \
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

static inline uint32_t cqufs_tobe32(uint32_t a) {
    return cqufs_frombe32(a);
}
/*********************************************************************************************************
  说明：用多项式= 0x04c11db7计算CRC-32
*********************************************************************************************************/
uint32_t cqufs_crc(uint32_t crc, const void *buffer, size_t size);
/*********************************************************************************************************
  说明：分配内存，只有在缓冲区没有提供给cqufs时才使用
*********************************************************************************************************/
static inline void *cqufs_malloc(size_t size) {
#ifndef CQUFS_NO_MALLOC
    return lib_malloc(size);
#else
    (void)size;
    return NULL;
#endif
}
/*********************************************************************************************************
  说明：释放内存，只在不给cqufs提供缓冲区的情况下使用
*********************************************************************************************************/
static inline void cqufs_free(void *p) {
#ifndef CQUFS_NO_MALLOC
    free(p);
#else
    (void)p;
#endif
}


#ifdef __cplusplus
} /* 外部 "C" */
#endif

#endif
#endif
