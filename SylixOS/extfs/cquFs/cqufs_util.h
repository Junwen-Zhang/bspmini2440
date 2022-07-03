/*********************************************************************************************************
**
**                                    �й������Դ��֯
**
**                                   Ƕ��ʽʵʱ����ϵͳ
**
**                                     SylixOS(TM)
**
**                               Copyright All Rights Reserved
**
**--------------�ļ���Ϣ--------------------------------------------------------------------------------
**
** ��   ��   ��: cqufs_util.h
**
** ��   ��   ��: cqu Group
**
** �ļ���������: 2022 �� 06 �� 04 ��
**
** ��        ��: cqufs��ع��߰���h�ļ�
*********************************************************************************************************/
#ifndef CQUFS_UTIL_H
#define CQUFS_UTIL_H
/*********************************************************************************************************
  ˵����ͨ����CQUFS_CONFIG����ΪҪ������ͷ�ļ�(-DCQUFS_CONFIG= CQUFS_CONFIG .h)���û�����ʹ���Լ�������������cqufs_util.h�����ʹ����CQUFS_CONFIG���򲻻ᷢ���κ�Ĭ�ϵ�utils�����ұ����������ļ��ṩ�����鸴��cqufs_util.h��������Ҫ�����޸ġ�
*********************************************************************************************************/
#ifdef CQUFS_CONFIG
#define CQUFS_STRINGIZE(x) CQUFS_STRINGIZE2(x)
#define CQUFS_STRINGIZE2(x) #x
#include CQUFS_STRINGIZE(CQUFS_CONFIG)
#else
/*********************************************************************************************************
  ˵����ϵͳ����
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
  ˵�����꣬������ϵͳ�ض��İ�װ���滻����Щ��Ĳ��������и����ã���Ϊ����ɾ����Щ���Լ��ٴ���ռ��
*********************************************************************************************************/
/*********************************************************************************************************
  ˵������־��¼����
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
  ˵�������ú�������Щ�������ܻᱻ����Ч���ض��ڹ�������ʵ����ȡ����CQUFS_NO_INTRINSICSΪ�˵��Ե�Ŀ�ģ������˸�����Ļ���Cʵ��,�����޷���32λ���ֵ���С/�����
*********************************************************************************************************/
static inline uint32_t cqufs_max(uint32_t a, uint32_t b) {
    return (a > b) ? a : b;
}

static inline uint32_t cqufs_min(uint32_t a, uint32_t b) {
    return (a < b) ? a : b;
}
/*********************************************************************************************************
  ˵�������뵽��С���������
*********************************************************************************************************/
static inline uint32_t cqufs_aligndown(uint32_t a, uint32_t alignment) {
    return a - (a % alignment);
}

static inline uint32_t cqufs_alignup(uint32_t a, uint32_t alignment) {
    return cqufs_aligndown(a + alignment-1, alignment);
}
/*********************************************************************************************************
  ˵��������ڻ����a��2����С��
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
  ˵��������cqufs_ctz(0)��β������������������δ����
*********************************************************************************************************/
static inline uint32_t cqufs_ctz(uint32_t a) {
#if !defined(CQUFS_NO_INTRINSICS) && defined(__GNUC__)
    return __builtin_ctz(a);
#else
    return cqufs_npw2((a & -a) + 1) - 1;
#endif
}
/*********************************************************************************************************
  ˵��������a�ж�����1�ĸ���
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
  ˵������a��b�����бȽϣ����Ǻ��������a��b֮��ľ���
*********************************************************************************************************/
static inline int cqufs_scmp(uint32_t a, uint32_t b) {
    return (int)(unsigned)(a - b);
}
/*********************************************************************************************************
  ˵������32λС��˳��ͱ���˳��֮�����ת��
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
  ˵������32λ���˳��ͱ���˳��֮�����ת��
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
  ˵�����ö���ʽ= 0x04c11db7����CRC-32
*********************************************************************************************************/
uint32_t cqufs_crc(uint32_t crc, const void *buffer, size_t size);
/*********************************************************************************************************
  ˵���������ڴ棬ֻ���ڻ�����û���ṩ��cqufsʱ��ʹ��
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
  ˵�����ͷ��ڴ棬ֻ�ڲ���cqufs�ṩ�������������ʹ��
*********************************************************************************************************/
static inline void cqufs_free(void *p) {
#ifndef CQUFS_NO_MALLOC
    free(p);
#else
    (void)p;
#endif
}


#ifdef __cplusplus
} /* �ⲿ "C" */
#endif

#endif
#endif
