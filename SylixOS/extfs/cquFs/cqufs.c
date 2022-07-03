
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
** ��   ��   ��: cqufs.c
**
** ��   ��   ��: cqu Group
**
** �ļ���������: 2022 �� 06 �� 04 ��
**
** ��        ��: cqufsʵ���ļ�
*********************************************************************************************************/
#include "cqufs.h"
#include "cqufs_util.h"

/*********************************************************************************************************
  ������ʹ�õ�һЩ����
*********************************************************************************************************/
#define CQUFS_BLOCK_NULL ((cqufs_block_t)-1)
#define CQUFS_BLOCK_INLINE ((cqufs_block_t)-2)

enum {
    CQUFS_OK_RELOCATED = 1,
    CQUFS_OK_DROPPED   = 2,
    CQUFS_OK_ORPHANED  = 3,
};

enum {
    CQUFS_CMP_EQ = 0,
    CQUFS_CMP_LT = 1,
    CQUFS_CMP_GT = 2,
};

/*********************************************************************************************************
  ������豸����
*********************************************************************************************************/

static inline void cqufs_cache_drop(cqufs_t *cqufs, cqufs_cache_t *rcache) {
/*********************************************************************************************************
˵������ҪΪ�㣬���������ֻ���Ļ�ֻ����ֻ���ģ�������С������ͬ������д��(�����¶�λ�ڼ�)
*********************************************************************************************************/
    (void)cqufs;
    rcache->block = CQUFS_BLOCK_NULL;
}

static inline void cqufs_cache_zero(cqufs_t *cqufs, cqufs_cache_t *pcache) {
    /* ˵������й¶��������Ϣй¶ */
    memset(pcache->buffer, 0xff, cqufs->cfg->cache_size);
    pcache->block = CQUFS_BLOCK_NULL;
}

static int cqufs_bd_read(cqufs_t *cqufs,
        const cqufs_cache_t *pcache, cqufs_cache_t *rcache, cqufs_size_t hint,
        cqufs_block_t block, cqufs_off_t off,
        void *buffer, cqufs_size_t size) {
    uint8_t *data = buffer;
    if (block >= cqufs->cfg->block_count ||
            off+size > cqufs->cfg->block_size) {
        return CQUFS_ERR_CORRUPT;
    }

    while (size > 0) {
        cqufs_size_t diff = size;

        if (pcache && block == pcache->block &&
                off < pcache->off + pcache->size) {
            if (off >= pcache->off) { /*  �Ѿ���pcache�У�   */
                diff = cqufs_min(diff, pcache->size - (off-pcache->off));
                memcpy(data, &pcache->buffer[off-pcache->off], diff);

                data += diff;
                off += diff;
                size -= diff;
                continue;
            }

            diff = cqufs_min(diff, pcache->off-off); /*  pcache����   */
        }

        if (block == rcache->block &&
                off < rcache->off + rcache->size) {
            if (off >= rcache->off) { /*  �Ѿ���rcache�У�   */
                diff = cqufs_min(diff, rcache->size - (off-rcache->off));
                memcpy(data, &rcache->buffer[off-rcache->off], diff);

                data += diff;
                off += diff;
                size -= diff;
                continue;
            }

            diff = cqufs_min(diff, rcache->off-off);/*  rcache����   */
        }

        if (size >= hint && off % cqufs->cfg->read_size == 0 &&
                size >= cqufs->cfg->read_size) { /* english bypass cache  */

            diff = cqufs_aligndown(diff, cqufs->cfg->read_size);
            int err = cqufs->cfg->read(cqufs->cfg, block, off, data, diff);
            if (err) {
                return err;
            }

            data += diff;
            off += diff;
            size -= diff;
            continue;
        }

        CQUFS_ASSERT(block < cqufs->cfg->block_count); /*  ���ص����棬��һ������������ʧ��   */
        rcache->block = block;
        rcache->off = cqufs_aligndown(off, cqufs->cfg->read_size);
        rcache->size = cqufs_min(
                cqufs_min(
                    cqufs_alignup(off+hint, cqufs->cfg->read_size),
                    cqufs->cfg->block_size)
                - rcache->off,
                cqufs->cfg->cache_size);
        int err = cqufs->cfg->read(cqufs->cfg, rcache->block,
                rcache->off, rcache->buffer, rcache->size);
        CQUFS_ASSERT(err <= 0);
        if (err) {
            return err;
        }
    }

    return 0;
}

static int cqufs_bd_cmp(cqufs_t *cqufs,
        const cqufs_cache_t *pcache, cqufs_cache_t *rcache, cqufs_size_t hint,
        cqufs_block_t block, cqufs_off_t off,
        const void *buffer, cqufs_size_t size) {
    const uint8_t *data = buffer;
    cqufs_size_t diff = 0;
    cqufs_off_t i;

    for (i = 0; i < size; i += diff) {
        uint8_t dat[8];

        diff = cqufs_min(size-i, sizeof(dat));
        int res = cqufs_bd_read(cqufs,
                pcache, rcache, hint-i,
                block, off+i, &dat, diff);
        if (res) {
            return res;
        }

        res = memcmp(dat, data + i, diff);
        if (res) {
            return res < 0 ? CQUFS_CMP_LT : CQUFS_CMP_GT;
        }
    }

    return CQUFS_CMP_EQ;
}

#ifndef CQUFS_READONLY
static int cqufs_bd_flush(cqufs_t *cqufs,
        cqufs_cache_t *pcache, cqufs_cache_t *rcache, bool validate) {
    if (pcache->block != CQUFS_BLOCK_NULL && pcache->block != CQUFS_BLOCK_INLINE) {
        CQUFS_ASSERT(pcache->block < cqufs->cfg->block_count);
        cqufs_size_t diff = cqufs_alignup(pcache->size, cqufs->cfg->prog_size);
        int err = cqufs->cfg->prog(cqufs->cfg, pcache->block,
                pcache->off, pcache->buffer, diff);
        CQUFS_ASSERT(err <= 0);
        if (err) {
            return err;
        }

        if (validate) { /* �������ϵ����� */
            cqufs_cache_drop(cqufs, rcache);
            int res = cqufs_bd_cmp(cqufs,
                    NULL, rcache, diff,
                    pcache->block, pcache->off, pcache->buffer, diff);
            if (res < 0) {
                return res;
            }

            if (res != CQUFS_CMP_EQ) {
                return CQUFS_ERR_CORRUPT;
            }
        }

        cqufs_cache_zero(cqufs, pcache);
    }

    return 0;
}
#endif

#ifndef CQUFS_READONLY
static int cqufs_bd_sync(cqufs_t *cqufs,
        cqufs_cache_t *pcache, cqufs_cache_t *rcache, bool validate) {
    cqufs_cache_drop(cqufs, rcache);

    int err = cqufs_bd_flush(cqufs, pcache, rcache, validate);
    if (err) {
        return err;
    }

    err = cqufs->cfg->sync(cqufs->cfg);
    CQUFS_ASSERT(err <= 0);
    return err;
}
#endif

#ifndef CQUFS_READONLY
static int cqufs_bd_prog(cqufs_t *cqufs,
        cqufs_cache_t *pcache, cqufs_cache_t *rcache, bool validate,
        cqufs_block_t block, cqufs_off_t off,
        const void *buffer, cqufs_size_t size) {
    const uint8_t *data = buffer;
    CQUFS_ASSERT(block == CQUFS_BLOCK_INLINE || block < cqufs->cfg->block_count);
    CQUFS_ASSERT(off + size <= cqufs->cfg->block_size);

    while (size > 0) {
        if (block == pcache->block &&
                off >= pcache->off &&
                off < pcache->off + cqufs->cfg->cache_size) { /* �Ƿ��Ѿ���pcache */
            cqufs_size_t diff = cqufs_min(size,
                    cqufs->cfg->cache_size - (off-pcache->off));
            memcpy(&pcache->buffer[off-pcache->off], data, diff);

            data += diff;
            off += diff;
            size -= diff;

            pcache->size = cqufs_max(pcache->size, off - pcache->off);
            if (pcache->size == cqufs->cfg->cache_size) { 
                int err = cqufs_bd_flush(cqufs, pcache, rcache, validate);/* ��������ˣ��ͻ�����flush pcache */
                if (err) {
                    return err;
                }
            }

            continue;
        }

/*********************************************************************************************************
  ˵����pcache���뱻flush��ͨ��programming�����������ֶ�flush
*********************************************************************************************************/
        CQUFS_ASSERT(pcache->block == CQUFS_BLOCK_NULL);

        pcache->block = block; /* ׼��pcache����һ������������ʧ�� */
        pcache->off = cqufs_aligndown(off, cqufs->cfg->prog_size);
        pcache->size = 0;
    }

    return 0;
}
#endif

#ifndef CQUFS_READONLY
static int cqufs_bd_erase(cqufs_t *cqufs, cqufs_block_t block) {
    CQUFS_ASSERT(block < cqufs->cfg->block_count);
    int err = cqufs->cfg->erase(cqufs->cfg, block);
    CQUFS_ASSERT(err <= 0);
    return err;
}
#endif

/*********************************************************************************************************
  С���ͼ����ʵ�ù���
*********************************************************************************************************/
/*********************************************************************************************************
  �ڿ���ϵĲ���
*********************************************************************************************************/
static inline void cqufs_pair_swap(cqufs_block_t pair[2]) {
    cqufs_block_t t = pair[0];
    pair[0] = pair[1];
    pair[1] = t;
}

static inline bool cqufs_pair_isnull(const cqufs_block_t pair[2]) {
    return pair[0] == CQUFS_BLOCK_NULL || pair[1] == CQUFS_BLOCK_NULL;
}

static inline int cqufs_pair_cmp(
        const cqufs_block_t paira[2],
        const cqufs_block_t pairb[2]) {
    return !(paira[0] == pairb[0] || paira[1] == pairb[1] ||
             paira[0] == pairb[1] || paira[1] == pairb[0]);
}

#ifndef CQUFS_READONLY
static inline bool cqufs_pair_sync(
        const cqufs_block_t paira[2],
        const cqufs_block_t pairb[2]) {
    return (paira[0] == pairb[0] && paira[1] == pairb[1]) ||
           (paira[0] == pairb[1] && paira[1] == pairb[0]);
}
#endif

static inline void cqufs_pair_fromle32(cqufs_block_t pair[2]) {
    pair[0] = cqufs_fromle32(pair[0]);
    pair[1] = cqufs_fromle32(pair[1]);
}

#ifndef CQUFS_READONLY
static inline void cqufs_pair_tole32(cqufs_block_t pair[2]) {
    pair[0] = cqufs_tole32(pair[0]);
    pair[1] = cqufs_tole32(pair[1]);
}
#endif
/*********************************************************************************************************
  ��32λentry tags�Ĳ���
*********************************************************************************************************/
typedef uint32_t cqufs_tag_t;
typedef int32_t cqufs_stag_t;

#define CQUFS_MKTAG(type, id, size) \
    (((cqufs_tag_t)(type) << 20) | ((cqufs_tag_t)(id) << 10) | (cqufs_tag_t)(size))

#define CQUFS_MKTAG_IF(cond, type, id, size) \
    ((cond) ? CQUFS_MKTAG(type, id, size) : CQUFS_MKTAG(CQUFS_FROM_NOOP, 0, 0))

#define CQUFS_MKTAG_IF_ELSE(cond, type1, id1, size1, type2, id2, size2) \
    ((cond) ? CQUFS_MKTAG(type1, id1, size1) : CQUFS_MKTAG(type2, id2, size2))

static inline bool cqufs_tag_isvalid(cqufs_tag_t tag) {
    return !(tag & 0x80000000);
}

static inline bool cqufs_tag_isdelete(cqufs_tag_t tag) {
    return ((int32_t)(tag << 22) >> 22) == -1;
}

static inline uint16_t cqufs_tag_type1(cqufs_tag_t tag) {
    return (tag & 0x70000000) >> 20;
}

static inline uint16_t cqufs_tag_type3(cqufs_tag_t tag) {
    return (tag & 0x7ff00000) >> 20;
}

static inline uint8_t cqufs_tag_chunk(cqufs_tag_t tag) {
    return (tag & 0x0ff00000) >> 20;
}

static inline int8_t cqufs_tag_splice(cqufs_tag_t tag) {
    return (int8_t)cqufs_tag_chunk(tag);
}

static inline uint16_t cqufs_tag_id(cqufs_tag_t tag) {
    return (tag & 0x000ffc00) >> 10;
}

static inline cqufs_size_t cqufs_tag_size(cqufs_tag_t tag) {
    return tag & 0x000003ff;
}

static inline cqufs_size_t cqufs_tag_dsize(cqufs_tag_t tag) {
    return sizeof(tag) + cqufs_tag_size(tag + cqufs_tag_isdelete(tag));
}
/*********************************************************************************************************
  �������б������ԵĲ���
*********************************************************************************************************/
struct cqufs_mattr {
    cqufs_tag_t tag;
    const void *buffer;
};

struct cqufs_diskoff {
    cqufs_block_t block;
    cqufs_off_t off;
};

#define CQUFS_MKATTRS(...) \
    (struct cqufs_mattr[]){__VA_ARGS__}, \
    sizeof((struct cqufs_mattr[]){__VA_ARGS__}) / sizeof(struct cqufs_mattr)
/*********************************************************************************************************
  ��ȫ��״̬�Ĳ���
*********************************************************************************************************/
static inline void cqufs_gstate_xor(cqufs_gstate_t *a, const cqufs_gstate_t *b) {
    int i;
    for (i = 0; i < 3; i++) {
        ((uint32_t*)a)[i] ^= ((const uint32_t*)b)[i];
    }
}

static inline bool cqufs_gstate_iszero(const cqufs_gstate_t *a) {
    int i;
    for (i = 0; i < 3; i++) {
        if (((uint32_t*)a)[i] != 0) {
            return false;
        }
    }
    return true;
}

#ifndef CQUFS_READONLY
static inline bool cqufs_gstate_hasorphans(const cqufs_gstate_t *a) {
    return cqufs_tag_size(a->tag);
}

static inline uint8_t cqufs_gstate_getorphans(const cqufs_gstate_t *a) {
    return cqufs_tag_size(a->tag);
}

static inline bool cqufs_gstate_hasmove(const cqufs_gstate_t *a) {
    return cqufs_tag_type1(a->tag);
}
#endif

static inline bool cqufs_gstate_hasmovehere(const cqufs_gstate_t *a,
        const cqufs_block_t *pair) {
    return cqufs_tag_type1(a->tag) && cqufs_pair_cmp(a->pair, pair) == 0;
}

static inline void cqufs_gstate_fromle32(cqufs_gstate_t *a) {
    a->tag     = cqufs_fromle32(a->tag);
    a->pair[0] = cqufs_fromle32(a->pair[0]);
    a->pair[1] = cqufs_fromle32(a->pair[1]);
}

#ifndef CQUFS_READONLY
static inline void cqufs_gstate_tole32(cqufs_gstate_t *a) {
    a->tag     = cqufs_tole32(a->tag);
    a->pair[0] = cqufs_tole32(a->pair[0]);
    a->pair[1] = cqufs_tole32(a->pair[1]);
}
#endif
/*********************************************************************************************************
  �����ֽ�˳�����
*********************************************************************************************************/
static void cqufs_ctz_fromle32(struct cqufs_ctz *ctz) {
    ctz->head = cqufs_fromle32(ctz->head);
    ctz->size = cqufs_fromle32(ctz->size);
}

#ifndef CQUFS_READONLY
static void cqufs_ctz_tole32(struct cqufs_ctz *ctz) {
    ctz->head = cqufs_tole32(ctz->head);
    ctz->size = cqufs_tole32(ctz->size);
}
#endif

static inline void cqufs_superblock_fromle32(cqufs_superblock_t *superblock) {
    superblock->version     = cqufs_fromle32(superblock->version);
    superblock->block_size  = cqufs_fromle32(superblock->block_size);
    superblock->block_count = cqufs_fromle32(superblock->block_count);
    superblock->name_max    = cqufs_fromle32(superblock->name_max);
    superblock->file_max    = cqufs_fromle32(superblock->file_max);
    superblock->attr_max    = cqufs_fromle32(superblock->attr_max);
}

#ifndef CQUFS_READONLY
static inline void cqufs_superblock_tole32(cqufs_superblock_t *superblock) {
    superblock->version     = cqufs_tole32(superblock->version);
    superblock->block_size  = cqufs_tole32(superblock->block_size);
    superblock->block_count = cqufs_tole32(superblock->block_count);
    superblock->name_max    = cqufs_tole32(superblock->name_max);
    superblock->file_max    = cqufs_tole32(superblock->file_max);
    superblock->attr_max    = cqufs_tole32(superblock->attr_max);
}
#endif

#ifndef CQUFS_NO_ASSERT
static bool cqufs_mlist_isopen(struct cqufs_mlist *head,
        struct cqufs_mlist *node) {
    struct cqufs_mlist **p;
    for (p = &head; *p; p = &(*p)->next) {
        if (*p == (struct cqufs_mlist*)node) {
            return true;
        }
    }

    return false;
}
#endif

static void cqufs_mlist_remove(cqufs_t *cqufs, struct cqufs_mlist *mlist) {
    struct cqufs_mlist **p;
    for (p = &cqufs->mlist; *p; p = &(*p)->next) {
        if (*p == mlist) {
            *p = (*p)->next;
            break;
        }
    }
}

static void cqufs_mlist_append(cqufs_t *cqufs, struct cqufs_mlist *mlist) {
    mlist->next = cqufs->mlist;
    cqufs->mlist = mlist;
}

/*********************************************************************************************************
  Ԥ���������ڲ�����
*********************************************************************************************************/
#ifndef CQUFS_READONLY
static int cqufs_dir_commit(cqufs_t *cqufs, cqufs_mdir_t *dir,
        const struct cqufs_mattr *attrs, int attrcount);
static int cqufs_dir_compact(cqufs_t *cqufs,
        cqufs_mdir_t *dir, const struct cqufs_mattr *attrs, int attrcount,
        cqufs_mdir_t *source, uint16_t begin, uint16_t end);
static cqufs_ssize_t cqufs_file_flushedwrite(cqufs_t *cqufs, cqufs_file_t *file,
        const void *buffer, cqufs_size_t size);
static cqufs_ssize_t cqufs_file_rawwrite(cqufs_t *cqufs, cqufs_file_t *file,
        const void *buffer, cqufs_size_t size);
static int cqufs_file_rawsync(cqufs_t *cqufs, cqufs_file_t *file);
static int cqufs_file_outline(cqufs_t *cqufs, cqufs_file_t *file);
static int cqufs_file_flush(cqufs_t *cqufs, cqufs_file_t *file);

static int cqufs_fs_deorphan(cqufs_t *cqufs, bool powerloss);
static int cqufs_fs_preporphans(cqufs_t *cqufs, int8_t orphans);
static void cqufs_fs_prepmove(cqufs_t *cqufs,
        uint16_t id, const cqufs_block_t pair[2]);
static int cqufs_fs_pred(cqufs_t *cqufs, const cqufs_block_t dir[2],
        cqufs_mdir_t *pdir);
static cqufs_stag_t cqufs_fs_parent(cqufs_t *cqufs, const cqufs_block_t dir[2],
        cqufs_mdir_t *parent);
static int cqufs_fs_forceconsistency(cqufs_t *cqufs);
#endif

#ifdef CQUFS_MIGRATE
static int cqufs1_traverse(cqufs_t *cqufs,
        int (*cb)(void*, cqufs_block_t), void *data);
#endif

static int cqufs_dir_rawrewind(cqufs_t *cqufs, cqufs_dir_t *dir);

static cqufs_ssize_t cqufs_file_flushedread(cqufs_t *cqufs, cqufs_file_t *file,
        void *buffer, cqufs_size_t size);
static cqufs_ssize_t cqufs_file_rawread(cqufs_t *cqufs, cqufs_file_t *file,
        void *buffer, cqufs_size_t size);
static int cqufs_file_rawclose(cqufs_t *cqufs, cqufs_file_t *file);
static cqufs_soff_t cqufs_file_rawsize(cqufs_t *cqufs, cqufs_file_t *file);

static cqufs_ssize_t cqufs_fs_rawsize(cqufs_t *cqufs);
static int cqufs_fs_rawtraverse(cqufs_t *cqufs,
        int (*cb)(void *data, cqufs_block_t block), void *data,
        bool includeorphans);

static int cqufs_deinit(cqufs_t *cqufs);
static int cqufs_rawunmount(cqufs_t *cqufs);

/*********************************************************************************************************
  �������
*********************************************************************************************************/
#ifndef CQUFS_READONLY
static int cqufs_alloc_lookahead(void *p, cqufs_block_t block) {
    cqufs_t *cqufs = (cqufs_t*)p;
    cqufs_block_t off = ((block - cqufs->free.off)
            + cqufs->cfg->block_count) % cqufs->cfg->block_count;

    if (off < cqufs->free.size) {
        cqufs->free.buffer[off / 32] |= 1U << (off % 32);
    }

    return 0;
}
#endif
/*********************************************************************************************************
  �����ѷ���Ŀ����ύ���ļ�ϵͳ������Ϊ�˷�ֹ�����ύ���������б������ռ�
*********************************************************************************************************/
static void cqufs_alloc_ack(cqufs_t *cqufs) {
    cqufs->free.ack = cqufs->cfg->block_count;
}
/*********************************************************************************************************
  ɾ��ǰ�򻺳����������ڹ��غ�ʧ�ܵı����ڼ����ģ��Ա�����Ч��ǰ��״̬
*********************************************************************************************************/
static void cqufs_alloc_drop(cqufs_t *cqufs) {
    cqufs->free.size = 0;
    cqufs->free.i = 0;
    cqufs_alloc_ack(cqufs);
}

#ifndef CQUFS_READONLY
static int cqufs_alloc(cqufs_t *cqufs, cqufs_block_t *block) {
    while (true) {
        while (cqufs->free.i != cqufs->free.size) {
            cqufs_block_t off = cqufs->free.i;
            cqufs->free.i += 1;
            cqufs->free.ack -= 1;

            if (!(cqufs->free.buffer[off / 32] & (1U << (off % 32)))) { /* �ҵ�һ�����еĿ� */
                *block = (cqufs->free.off + off) % cqufs->cfg->block_count;

                while (cqufs->free.i != cqufs->free.size &&
                        (cqufs->free.buffer[cqufs->free.i / 32]
                            & (1U << (cqufs->free.i % 32)))) {  /*����Ѱ����һ��off��ʹ��alloc ack����discredit�ɵ�lookahead block */
                    cqufs->free.i += 1;
                    cqufs->free.ack -= 1;
                }

                return 0;
            }
        }

        if (cqufs->free.ack == 0) {/* ��������Ƿ�鿴�����ϴ�ack���������п� */
            CQUFS_ERROR("No more free space %"PRIu32,
                    cqufs->free.i + cqufs->free.off);
            return CQUFS_ERR_NOSPC;
        }

        cqufs->free.off = (cqufs->free.off + cqufs->free.size)
                % cqufs->cfg->block_count;
        cqufs->free.size = cqufs_min(8*cqufs->cfg->lookahead_size, cqufs->free.ack);
        cqufs->free.i = 0;

        memset(cqufs->free.buffer, 0, cqufs->cfg->lookahead_size); /* ��tree���ҵ����п������ */
        int err = cqufs_fs_rawtraverse(cqufs, cqufs_alloc_lookahead, cqufs, true);
        if (err) {
            cqufs_alloc_drop(cqufs);
            return err;
        }
    }
}
#endif

/*********************************************************************************************************
  Ԫ���ݶԺ�Ŀ¼����
*********************************************************************************************************/
static cqufs_stag_t cqufs_dir_getslice(cqufs_t *cqufs, const cqufs_mdir_t *dir,
        cqufs_tag_t gmask, cqufs_tag_t gtag,
        cqufs_off_t goff, void *gbuffer, cqufs_size_t gsize) {
    cqufs_off_t off = dir->off;
    cqufs_tag_t ntag = dir->etag;
    cqufs_stag_t gdiff = 0;

    if (cqufs_gstate_hasmovehere(&cqufs->gdisk, dir->pair) &&
            cqufs_tag_id(gmask) != 0 &&
            cqufs_tag_id(cqufs->gdisk.tag) <= cqufs_tag_id(gtag)) {
        gdiff -= CQUFS_MKTAG(0, 1, 0);  /* �ϳɵĶ��� */
    }

    while (off >= sizeof(cqufs_tag_t) + cqufs_tag_dsize(ntag)) { /* ������dir��(�ӿ�����ٶ�) */
        off -= cqufs_tag_dsize(ntag);
        cqufs_tag_t tag = ntag;
        int err = cqufs_bd_read(cqufs,
                NULL, &cqufs->rcache, sizeof(ntag),
                dir->pair[0], off, &ntag, sizeof(ntag));
        if (err) {
            return err;
        }

        ntag = (cqufs_frombe32(ntag) ^ tag) & 0x7fffffff;

        if (cqufs_tag_id(gmask) != 0 &&
                cqufs_tag_type1(tag) == CQUFS_TYPE_SPLICE &&
                cqufs_tag_id(tag) <= cqufs_tag_id(gtag - gdiff)) {
            if (tag == (CQUFS_MKTAG(CQUFS_TYPE_CREATE, 0, 0) |
                    (CQUFS_MKTAG(0, 0x3ff, 0) & (gtag - gdiff)))) { /* �ҵ����ֵ�λ�� */
                return CQUFS_ERR_NOENT;
            }

            gdiff += CQUFS_MKTAG(0, cqufs_tag_splice(tag), 0); /* ��splices���ƶ� */
        }

        if ((gmask & tag) == (gmask & (gtag - gdiff))) {
            if (cqufs_tag_isdelete(tag)) {
                return CQUFS_ERR_NOENT;
            }

            cqufs_size_t diff = cqufs_min(cqufs_tag_size(tag), gsize);
            err = cqufs_bd_read(cqufs,
                    NULL, &cqufs->rcache, diff,
                    dir->pair[0], off+sizeof(tag)+goff, gbuffer, diff);
            if (err) {
                return err;
            }

            memset((uint8_t*)gbuffer + diff, 0, gsize - diff);

            return tag + gdiff;
        }
    }

    return CQUFS_ERR_NOENT;
}

static cqufs_stag_t cqufs_dir_get(cqufs_t *cqufs, const cqufs_mdir_t *dir,
        cqufs_tag_t gmask, cqufs_tag_t gtag, void *buffer) {
    return cqufs_dir_getslice(cqufs, dir,
            gmask, gtag,
            0, buffer, cqufs_tag_size(gtag));
}

static int cqufs_dir_getread(cqufs_t *cqufs, const cqufs_mdir_t *dir,
        const cqufs_cache_t *pcache, cqufs_cache_t *rcache, cqufs_size_t hint,
        cqufs_tag_t gmask, cqufs_tag_t gtag,
        cqufs_off_t off, void *buffer, cqufs_size_t size) {
    uint8_t *data = buffer;
    if (off+size > cqufs->cfg->block_size) {
        return CQUFS_ERR_CORRUPT;
    }

    while (size > 0) {
        cqufs_size_t diff = size;

        if (pcache && pcache->block == CQUFS_BLOCK_INLINE &&
                off < pcache->off + pcache->size) {
            if (off >= pcache->off) { /* �Ƿ��Ѿ�������pcache  */
                diff = cqufs_min(diff, pcache->size - (off-pcache->off));
                memcpy(data, &pcache->buffer[off-pcache->off], diff);

                data += diff;
                off += diff;
                size -= diff;
                continue;
            }

            diff = cqufs_min(diff, pcache->off-off); /* pcache���� */
        }

        if (rcache->block == CQUFS_BLOCK_INLINE &&
                off < rcache->off + rcache->size) {
            if (off >= rcache->off) { /* �Ƿ��Ѿ�������rcache  */
                diff = cqufs_min(diff, rcache->size - (off-rcache->off));
                memcpy(data, &rcache->buffer[off-rcache->off], diff);

                data += diff;
                off += diff;
                size -= diff;
                continue;
            }

            diff = cqufs_min(diff, rcache->off-off);/* rcache���� */
        }

        rcache->block = CQUFS_BLOCK_INLINE;  /* ��һ���������ʧ�ܣ��浽cache  */
        rcache->off = cqufs_aligndown(off, cqufs->cfg->read_size);
        rcache->size = cqufs_min(cqufs_alignup(off+hint, cqufs->cfg->read_size),
                cqufs->cfg->cache_size);
        int err = cqufs_dir_getslice(cqufs, dir, gmask, gtag,
                rcache->off, rcache->buffer, rcache->size);
        if (err < 0) {
            return err;
        }
    }

    return 0;
}

#ifndef CQUFS_READONLY
static int cqufs_dir_traverse_filter(void *p,
        cqufs_tag_t tag, const void *buffer) {
    cqufs_tag_t *filtertag = p;
    (void)buffer;

    uint32_t mask = (tag & CQUFS_MKTAG(0x100, 0, 0))
            ? CQUFS_MKTAG(0x7ff, 0x3ff, 0)
            : CQUFS_MKTAG(0x700, 0x3ff, 0); /* �����ڱ�ǩ�ṹ�е�Ψһλ�����ĸ����� */

    if ((mask & tag) == (mask & *filtertag) ||
            cqufs_tag_isdelete(*filtertag) ||
            (CQUFS_MKTAG(0x7ff, 0x3ff, 0) & tag) == (
                CQUFS_MKTAG(CQUFS_TYPE_DELETE, 0, 0) |
                    (CQUFS_MKTAG(0, 0x3ff, 0) & *filtertag))) {
        *filtertag = CQUFS_MKTAG(CQUFS_FROM_NOOP, 0, 0); /* ������� */
        return true;
    }

    if (cqufs_tag_type1(tag) == CQUFS_TYPE_SPLICE &&
            cqufs_tag_id(tag) <= cqufs_tag_id(*filtertag)) {
        *filtertag += CQUFS_MKTAG(0, cqufs_tag_splice(tag), 0);
    } /* ����Ƿ���Ҫ����Ѵ���/��ɾ����tags���е��� */

    return false;
}
#endif

#ifndef CQUFS_READONLY
/*********************************************************************************************************
 ˵����cqufs_dir_traverse�����ݹ����:
  �����ύ
    ->����
    ->����������
*********************************************************************************************************/
#define CQUFS_DIR_TRAVERSE_DEPTH 3

struct cqufs_dir_traverse {
    const cqufs_mdir_t *dir;
    cqufs_off_t off;
    cqufs_tag_t ptag;
    const struct cqufs_mattr *attrs;
    int attrcount;

    cqufs_tag_t tmask;
    cqufs_tag_t ttag;
    uint16_t begin;
    uint16_t end;
    int16_t diff;

    int (*cb)(void *data, cqufs_tag_t tag, const void *buffer);
    void *data;

    cqufs_tag_t tag;
    const void *buffer;
    struct cqufs_diskoff disk;
};

static int cqufs_dir_traverse(cqufs_t *cqufs,
        const cqufs_mdir_t *dir, cqufs_off_t off, cqufs_tag_t ptag,
        const struct cqufs_mattr *attrs, int attrcount,
        cqufs_tag_t tmask, cqufs_tag_t ttag,
        uint16_t begin, uint16_t end, int16_t diff,
        int (*cb)(void *data, cqufs_tag_t tag, const void *buffer), void *data) {
    /*********************************************************************************************************
     ˵����������������ǵݹ�ģ����н硣Ϊ��������ڹ��ߵķ�����û�в���Ҫ�Ĵ���ɱ�������ʹ����ʽ��ջ
    *********************************************************************************************************/
    struct cqufs_dir_traverse stack[CQUFS_DIR_TRAVERSE_DEPTH-1];
    unsigned sp = 0;
    int res;

    cqufs_tag_t tag;
    const void *buffer;
    struct cqufs_diskoff disk;
    while (true) { /* ����Ŀ¼��attrs */
        {
            if (off+cqufs_tag_dsize(ptag) < dir->off) {
                off += cqufs_tag_dsize(ptag);
                int err = cqufs_bd_read(cqufs,
                        NULL, &cqufs->rcache, sizeof(tag),
                        dir->pair[0], off, &tag, sizeof(tag));
                if (err) {
                    return err;
                }

                tag = (cqufs_frombe32(tag) ^ ptag) | 0x80000000;
                disk.block = dir->pair[0];
                disk.off = off+sizeof(cqufs_tag_t);
                buffer = &disk;
                ptag = tag;
            } else if (attrcount > 0) {
                tag = attrs[0].tag;
                buffer = attrs[0].buffer;
                attrs += 1;
                attrcount -= 1;
            } else {
                res = 0; /* ��ɱ������Ƿ�Ӷ�ջ���� */
                break;
            }

            cqufs_tag_t mask = CQUFS_MKTAG(0x7ff, 0, 0);   /* �Ƿ���Ҫ���� */
            if ((mask & tmask & tag) != (mask & tmask & ttag)) {
                continue;
            }

            if (cqufs_tag_id(tmask) != 0) {
                CQUFS_ASSERT(sp < CQUFS_DIR_TRAVERSE_DEPTH);
                /*********************************************************************************************************
                 ˵�����ݹ飬ɨ���ظ��������ݴ���/ɾ�����±�ǩ
                *********************************************************************************************************/
                stack[sp] = (struct cqufs_dir_traverse){
                    .dir        = dir,
                    .off        = off,
                    .ptag       = ptag,
                    .attrs      = attrs,
                    .attrcount  = attrcount,
                    .tmask      = tmask,
                    .ttag       = ttag,
                    .begin      = begin,
                    .end        = end,
                    .diff       = diff,
                    .cb         = cb,
                    .data       = data,
                    .tag        = tag,
                    .buffer     = buffer,
                    .disk       = disk,
                };
                sp += 1;

                dir = dir;
                off = off;
                ptag = ptag;
                attrs = attrs;
                attrcount = attrcount;
                tmask = 0;
                ttag = 0;
                begin = 0;
                end = 0;
                diff = 0;
                cb = cqufs_dir_traverse_filter;
                data = &stack[sp-1].tag;
                continue;
            }
        }

popped:
        if (cqufs_tag_id(tmask) != 0 &&
                !(cqufs_tag_id(tag) >= begin && cqufs_tag_id(tag) < end)) { /* �Ƿ���filter�ķ�Χ�� */
            continue;
        }

        if (cqufs_tag_type3(tag) == CQUFS_FROM_NOOP) { /* ����mcu�˲������������ */
            /* ʲôҲ���� */
        } else if (cqufs_tag_type3(tag) == CQUFS_FROM_MOVE) {
            /*********************************************************************************************************
            ˵����
            ���û�����������cqufs_dir_traverse��������ʱ���ܻ���ִ��ۼ��ߵ�Ƕ��ѭ��O(n^3)��
            ���������������Ϊcqufs_dir_traverse��ͼͨ��ԴĿ¼�еı�ǩ�����˱�ǩ���Ӷ�ʹ���Լ��Ĺ��˲��������ڶ���cqufs_dir_traverse��
            �����ύ
                ->����������
                ->����
                ->����������
            Ȼ��������ʵ���ϲ������Ĺ��˵ڶ����ǣ���Ϊ�ظ�����ڹ���ʱû��Ӱ�졣��������ʽ�������������Ҫ�ĵݹ���ˣ�������ʱ���O(n^3)���ٵ�O(n^2)��
            *********************************************************************************************************/
            if (cb == cqufs_dir_traverse_filter) {
                continue;
            }

            stack[sp] = (struct cqufs_dir_traverse){
                .dir        = dir,
                .off        = off,
                .ptag       = ptag,
                .attrs      = attrs,
                .attrcount  = attrcount,
                .tmask      = tmask,
                .ttag       = ttag,
                .begin      = begin,
                .end        = end,
                .diff       = diff,
                .cb         = cb,
                .data       = data,
                .tag        = CQUFS_MKTAG(CQUFS_FROM_NOOP, 0, 0),
            };
            sp += 1;

            uint16_t fromid = cqufs_tag_size(tag);
            uint16_t toid = cqufs_tag_id(tag);
            dir = buffer;
            off = 0;
            ptag = 0xffffffff;
            attrs = NULL;
            attrcount = 0;
            tmask = CQUFS_MKTAG(0x600, 0x3ff, 0);
            ttag = CQUFS_MKTAG(CQUFS_TYPE_STRUCT, 0, 0);
            begin = fromid;
            end = fromid+1;
            diff = toid-fromid+diff;
        } else if (cqufs_tag_type3(tag) == CQUFS_FROM_USERATTRS) {
            unsigned i;
            for (i = 0; i < cqufs_tag_size(tag); i++) {
                const struct cqufs_attr *a = buffer;
                res = cb(data, CQUFS_MKTAG(CQUFS_TYPE_USERATTR + a[i].type,
                        cqufs_tag_id(tag) + diff, a[i].size), a[i].buffer);
                if (res < 0) {
                    return res;
                }

                if (res) {
                    break;
                }
            }
        } else {
            res = cb(data, tag + CQUFS_MKTAG(0, diff, 0), buffer);
            if (res < 0) {
                return res;
            }

            if (res) {
                break;
            }
        }
    }

    if (sp > 0) { /* ��ջ�е��������أ���õ�����ǵ������е�����Ϊͬһ��Ŀ�ĵ�  */
        dir         = stack[sp-1].dir;
        off         = stack[sp-1].off;
        ptag        = stack[sp-1].ptag;
        attrs       = stack[sp-1].attrs;
        attrcount   = stack[sp-1].attrcount;
        tmask       = stack[sp-1].tmask;
        ttag        = stack[sp-1].ttag;
        begin       = stack[sp-1].begin;
        end         = stack[sp-1].end;
        diff        = stack[sp-1].diff;
        cb          = stack[sp-1].cb;
        data        = stack[sp-1].data;
        tag         = stack[sp-1].tag;
        buffer      = stack[sp-1].buffer;
        disk        = stack[sp-1].disk;
        sp -= 1;
        goto popped;
    } else {
        return res;
    }
}
#endif

static cqufs_stag_t cqufs_dir_fetchmatch(cqufs_t *cqufs,
        cqufs_mdir_t *dir, const cqufs_block_t pair[2],
        cqufs_tag_t fmask, cqufs_tag_t ftag, uint16_t *id,
        int (*cb)(void *data, cqufs_tag_t tag, const void *buffer), void *data) {/* �����ڻ�ȡ�����зǳ���Ч���ҵ���ǩ����Ϊ�����Ѿ�ɨ��������Ŀ¼ */
    cqufs_stag_t besttag = -1; 

    if (pair[0] >= cqufs->cfg->block_count || pair[1] >= cqufs->cfg->block_count) {
        return CQUFS_ERR_CORRUPT;
    } /* ����κ�һ�����ַ��Ч�����������ﷵ��CQUFS_ERR_CORRUPT�������Ժ�ԸöԵ�д����ܻ�ʧ�� */

    uint32_t revs[2] = {0, 0}; /* �ҵ������޸ĵĴ���� */
    int r = 0, i;
    printf("before for loop, cqufs_bd_read--------------------------\n");
    for (i = 0; i < 2; i++) {
        int err = cqufs_bd_read(cqufs,
                NULL, &cqufs->rcache, sizeof(revs[i]),
                pair[i], 0, &revs[i], sizeof(revs[i]));
        revs[i] = cqufs_fromle32(revs[i]);
        if (err && err != CQUFS_ERR_CORRUPT) {
            return err;
        }

        if (err != CQUFS_ERR_CORRUPT &&
                cqufs_scmp(revs[i], revs[(i+1)%2]) > 0) {
            r = i;
        }
    }
    printf("after for loop, cqufs_bd_read--------------------------\n");

    dir->pair[0] = pair[(r+0)%2];
    dir->pair[1] = pair[(r+1)%2];
    dir->rev = revs[(r+0)%2];
    dir->off = 0; /* nonzero��ʾ����һЩcommit */

    for (i = 0; i < 2; i++) { /* ����ɨ��tags����ȡʵ�ʵ�Ŀ¼���ҵ����ܵ�ƥ�� */
        cqufs_off_t off = 0;
        cqufs_tag_t ptag = 0xffffffff;

        uint16_t tempcount = 0;
        cqufs_block_t temptail[2] = {CQUFS_BLOCK_NULL, CQUFS_BLOCK_NULL};
        bool tempsplit = false;
        cqufs_stag_t tempbesttag = besttag;

        dir->rev = cqufs_tole32(dir->rev);
        uint32_t crc = cqufs_crc(0xffffffff, &dir->rev, sizeof(dir->rev));
        dir->rev = cqufs_fromle32(dir->rev);

        while (true) { /* ��ȡ��һ����ǩ */
            cqufs_tag_t tag;
            off += cqufs_tag_dsize(ptag);
            int err = cqufs_bd_read(cqufs,
                    NULL, &cqufs->rcache, cqufs->cfg->block_size,
                    dir->pair[0], off, &tag, sizeof(tag));
            if (err) {
                if (err == CQUFS_ERR_CORRUPT) { /* ���ܼ��� */
                    dir->erased = false;
                    break;
                }
                return err;
            }

            crc = cqufs_crc(crc, &tag, sizeof(tag));
            tag = cqufs_frombe32(tag) ^ ptag;

            /* ��һ���ύ��δ��̻����ǲ�����Ч��Χ�� */
            if (!cqufs_tag_isvalid(tag)) { /* ???��һ��commit��û��programmed��ɻ��߲�����Ч�ķ�Χ�� */
                dir->erased = (cqufs_tag_type1(ptag) == CQUFS_TYPE_CRC &&
                        dir->off % cqufs->cfg->prog_size == 0);
                break;
            } else if (off + cqufs_tag_dsize(tag) > cqufs->cfg->block_size) {
                dir->erased = false;
                break;
            }

            ptag = tag;

            if (cqufs_tag_type1(tag) == CQUFS_TYPE_CRC) { /* ���crc������ */
                uint32_t dcrc;
                err = cqufs_bd_read(cqufs,
                        NULL, &cqufs->rcache, cqufs->cfg->block_size,
                        dir->pair[0], off+sizeof(tag), &dcrc, sizeof(dcrc));
                if (err) {
                    if (err == CQUFS_ERR_CORRUPT) {
                        dir->erased = false;
                        break;
                    }
                    return err;
                }
                dcrc = cqufs_fromle32(dcrc);

                if (crc != dcrc) {
                    dir->erased = false;
                    break;
                }

                ptag ^= (cqufs_tag_t)(cqufs_tag_chunk(tag) & 1U) << 31; /* ������һλ */
            /*********************************************************************************************************
            ˵���������ǵ�CRC�����ļ�ϵͳ�����Ի�ȡα�������ע������������ʹ����һ��CRC��Ϊ���Ϻ�������Ϊ���㹻����ͷ���
            *********************************************************************************************************/
                cqufs->seed = cqufs_crc(cqufs->seed, &crc, sizeof(crc));

                besttag = tempbesttag; /* ���µ�ǰ�ҵ��� */
                dir->off = off + cqufs_tag_dsize(tag);
                dir->etag = ptag;
                dir->count = tempcount;
                dir->tail[0] = temptail[0];
                dir->tail[1] = temptail[1];
                dir->split = tempsplit;

                crc = 0xffffffff; /* ����crc  */
                continue;
            }
            /*********************************************************************************************************
            ˵�������ȶ�entry����CRCУ�飬ϣ���ܰ������ڻ�����
            *********************************************************************************************************/
            cqufs_off_t j;
            for (j = sizeof(tag); j < cqufs_tag_dsize(tag); j++) {
                uint8_t dat;
                err = cqufs_bd_read(cqufs,
                        NULL, &cqufs->rcache, cqufs->cfg->block_size,
                        dir->pair[0], off+j, &dat, 1);
                if (err) {
                    if (err == CQUFS_ERR_CORRUPT) {
                        dir->erased = false;
                        break;
                    }
                    return err;
                }

                crc = cqufs_crc(crc, &dat, 1);
            }

            if (cqufs_tag_type1(tag) == CQUFS_TYPE_NAME) { /* �Ƿ�ΪĿ¼�޸ı�ǩ */
                if (cqufs_tag_id(tag) >= tempcount) { /* �����Ҫ�Ļ������ļ������� */
                    tempcount = cqufs_tag_id(tag) + 1;
                }
            } else if (cqufs_tag_type1(tag) == CQUFS_TYPE_SPLICE) {
                tempcount += cqufs_tag_splice(tag);

                if (tag == (CQUFS_MKTAG(CQUFS_TYPE_DELETE, 0, 0) |
                        (CQUFS_MKTAG(0, 0x3ff, 0) & tempbesttag))) {
                    tempbesttag |= 0x80000000;
                } else if (tempbesttag != -1 &&
                        cqufs_tag_id(tag) <= cqufs_tag_id(tempbesttag)) {
                    tempbesttag += CQUFS_MKTAG(0, cqufs_tag_splice(tag), 0);
                }
            } else if (cqufs_tag_type1(tag) == CQUFS_TYPE_TAIL) {
                tempsplit = (cqufs_tag_chunk(tag) & 1);

                err = cqufs_bd_read(cqufs,
                        NULL, &cqufs->rcache, cqufs->cfg->block_size,
                        dir->pair[0], off+sizeof(tag), &temptail, 8);
                if (err) {
                    if (err == CQUFS_ERR_CORRUPT) {
                        dir->erased = false;
                        break;
                    }
                }
                cqufs_pair_fromle32(temptail);
            }

            if ((fmask & tag) == (fmask & ftag)) { /* ???���Ϊfetcher�ҵ�ƥ�� */
                int res = cb(data, tag, &(struct cqufs_diskoff){
                        dir->pair[0], off+sizeof(tag)});
                if (res < 0) {
                    if (res == CQUFS_ERR_CORRUPT) {
                        dir->erased = false;
                        break;
                    }
                    return res;
                }

                if (res == CQUFS_CMP_EQ) { /* �ҵ�ƥ�� */
                    tempbesttag = tag;
                } else if ((CQUFS_MKTAG(0x7ff, 0x3ff, 0) & tag) ==
                        (CQUFS_MKTAG(0x7ff, 0x3ff, 0) & tempbesttag)) {
                /*********************************************************************************************************
                ˵����������һ����ͬ�ı�ǩ�������ݲ�ƥ�䣬��һ����ζ��������õı�ǩ��������
                *********************************************************************************************************/
                    tempbesttag = -1;
                } else if (res == CQUFS_CMP_GT &&
                        cqufs_tag_id(tag) <= cqufs_tag_id(tempbesttag)) { /* �ҵ��˸��õ�ƥ�䣬���ټ�¼������ */
                    tempbesttag = tag | 0x80000000;
                }
            }
        }

        /*********************************************************************************************************
        ˵������Ϊ���������е��㹻��
        *********************************************************************************************************/
        if (dir->off > 0) {
            /* �ϳ��ƶ� */
            if (cqufs_gstate_hasmovehere(&cqufs->gdisk, dir->pair)) {
                if (cqufs_tag_id(cqufs->gdisk.tag) == cqufs_tag_id(besttag)) {
                    besttag |= 0x80000000;
                } else if (besttag != -1 &&
                        cqufs_tag_id(cqufs->gdisk.tag) < cqufs_tag_id(besttag)) {
                    besttag -= CQUFS_MKTAG(0, 1, 0);
                }
            }

            if (id) { /* �ҵ�tag �����ҵ���õ�id */
                *id = cqufs_min(cqufs_tag_id(besttag), dir->count);
            }

            if (cqufs_tag_isvalid(besttag)) {
                return besttag;
            } else if (cqufs_tag_id(besttag) < dir->count) {
                return CQUFS_ERR_NOENT;
            } else {
                return 0;
            }
        }

        cqufs_pair_swap(dir->pair); /* û�ҵ������������� */
        dir->rev = revs[(r+1)%2];
    }

    CQUFS_ERROR("Corrupted dir pair at {0x%"PRIx32", 0x%"PRIx32"}",
            dir->pair[0], dir->pair[1]);
    return CQUFS_ERR_CORRUPT;
}

static int cqufs_dir_fetch(cqufs_t *cqufs,
        cqufs_mdir_t *dir, const cqufs_block_t pair[2]) {
        /*********************************************************************************************************
        ˵����ע�⣬mask=-1, tag=-1��Զ����ƥ���ǩ����Ϊ���ģʽ��������Ч��λ
        *********************************************************************************************************/
    return (int)cqufs_dir_fetchmatch(cqufs, dir, pair,
            (cqufs_tag_t)-1, (cqufs_tag_t)-1, NULL, NULL, NULL);
}

static int cqufs_dir_getgstate(cqufs_t *cqufs, const cqufs_mdir_t *dir,
        cqufs_gstate_t *gstate) {
    cqufs_gstate_t temp;
    cqufs_stag_t res = cqufs_dir_get(cqufs, dir, CQUFS_MKTAG(0x7ff, 0, 0),
            CQUFS_MKTAG(CQUFS_TYPE_MOVESTATE, 0, sizeof(temp)), &temp);
    if (res < 0 && res != CQUFS_ERR_NOENT) {
        return res;
    }

    if (res != CQUFS_ERR_NOENT) { /* ���һ���ҵ������gstate */
        cqufs_gstate_fromle32(&temp);
        cqufs_gstate_xor(gstate, &temp);
    }

    return 0;
}

static int cqufs_dir_getinfo(cqufs_t *cqufs, cqufs_mdir_t *dir,
        uint16_t id, struct cqufs_info *info) {
    if (id == 0x3ff) { /* �Ը����ر���� */
        strcpy(info->name, "/");
        info->type = CQUFS_TYPE_DIR;
        return 0;
    }

    cqufs_stag_t tag = cqufs_dir_get(cqufs, dir, CQUFS_MKTAG(0x780, 0x3ff, 0),
            CQUFS_MKTAG(CQUFS_TYPE_NAME, id, cqufs->name_max+1), info->name);
    if (tag < 0) {
        return (int)tag;
    }

    info->type = cqufs_tag_type3(tag);

    struct cqufs_ctz ctz;
    tag = cqufs_dir_get(cqufs, dir, CQUFS_MKTAG(0x700, 0x3ff, 0),
            CQUFS_MKTAG(CQUFS_TYPE_STRUCT, id, sizeof(ctz)), &ctz);
    if (tag < 0) {
        return (int)tag;
    }
    cqufs_ctz_fromle32(&ctz);

    if (cqufs_tag_type3(tag) == CQUFS_TYPE_CTZSTRUCT) {
        info->size = ctz.size;
    } else if (cqufs_tag_type3(tag) == CQUFS_TYPE_INLINESTRUCT) {
        info->size = cqufs_tag_size(tag);
    }

    return 0;
}

struct cqufs_dir_find_match {
    cqufs_t *cqufs;
    const void *name;
    cqufs_size_t size;
};

static int cqufs_dir_find_match(void *data,
        cqufs_tag_t tag, const void *buffer) {
    struct cqufs_dir_find_match *name = data;
    cqufs_t *cqufs = name->cqufs;
    const struct cqufs_diskoff *disk = buffer;

    cqufs_size_t diff = cqufs_min(name->size, cqufs_tag_size(tag));
    int res = cqufs_bd_cmp(cqufs,                                 /* ˵��������̽��� */
            NULL, &cqufs->rcache, diff,
            disk->block, disk->off, name->name, diff);
    if (res != CQUFS_CMP_EQ) {
        return res;
    }

    if (name->size != cqufs_tag_size(tag)) { /* ֻ�д�С����ʱ����� */
        return (name->size < cqufs_tag_size(tag)) ? CQUFS_CMP_LT : CQUFS_CMP_GT;
    }

    /* ˵�����ҵ�һ��ƥ��! */
    return CQUFS_CMP_EQ;
}

static cqufs_stag_t cqufs_dir_find(cqufs_t *cqufs, cqufs_mdir_t *dir,
        const char **path, uint16_t *id) {

    const char *name = *path;     /*��������ҵ�·���������Ϊ�������� */
    if (id) {
        *id = 0x3ff;
    }

    cqufs_stag_t tag = CQUFS_MKTAG(CQUFS_TYPE_DIR, 0x3ff, 0); /*  Ĭ��Ϊroot dir   */
    dir->tail[0] = cqufs->root[0];
    dir->tail[1] = cqufs->root[1];

    while (true) {
nextname:

        name += strspn(name, "/");  /*  ����б��   */
        cqufs_size_t namelen = strcspn(name, "/");

        if ((namelen == 1 && memcmp(name, ".", 1) == 0) || /*  ������'.'��root '..'   */
            (namelen == 2 && memcmp(name, "..", 2) == 0)) {
            name += namelen;
            goto nextname;
        }

        const char *suffix = name + namelen;        /*  ����ƥ��'..������   */
        cqufs_size_t sufflen;
        int depth = 1;
        while (true) {
            suffix += strspn(suffix, "/");
            sufflen = strcspn(suffix, "/");
            if (sufflen == 0) {
                break;
            }

            if (sufflen == 2 && memcmp(suffix, "..", 2) == 0) {
                depth -= 1;
                if (depth == 0) {
                    name = suffix + sufflen;
                    goto nextname;
                }
            } else {
                depth += 1;
            }

            suffix += sufflen;
        }

        if (name[0] == '\0') {        /*   ����;��  */
            return tag;
        }

        *path = name;                          /*  ��������Ŀǰ�ķ���   */

        if (cqufs_tag_type3(tag) != CQUFS_TYPE_DIR) {                     /*  ֻ�е����ǵ���һ��Ŀ¼ʱ�Ż����   */
            return CQUFS_ERR_NOTDIR;
        }

        if (cqufs_tag_id(tag) != 0x3ff) {                     /*   ��ȡ�������  */
            cqufs_stag_t res = cqufs_dir_get(cqufs, dir, CQUFS_MKTAG(0x700, 0x3ff, 0),
                    CQUFS_MKTAG(CQUFS_TYPE_STRUCT, cqufs_tag_id(tag), 8), dir->tail);
            if (res < 0) {
                return res;
            }
            cqufs_pair_fromle32(dir->tail);
        }

        while (true) {                                  /*  ����������ƥ�����Ŀ   */
            tag = cqufs_dir_fetchmatch(cqufs, dir, dir->tail,
                    CQUFS_MKTAG(0x780, 0, 0),
                    CQUFS_MKTAG(CQUFS_TYPE_NAME, 0, namelen),
                    (strchr(name, '/') == NULL) ? id : NULL,                      /*  �Ƿ������Ҫ������   */
                    cqufs_dir_find_match, &(struct cqufs_dir_find_match){
                        cqufs, name, namelen});
            if (tag < 0) {
                return tag;
            }

            if (tag) {
                break;
            }

            if (!dir->split) {
                return CQUFS_ERR_NOENT;
            }
        }

        name += namelen;                     /*  ����һ������   */
    }
}

/*********************************************************************************************************
  �ṹ��cqufs_commit
*********************************************************************************************************/
struct cqufs_commit {
    cqufs_block_t block;
    cqufs_off_t off;
    cqufs_tag_t ptag;
    uint32_t crc;

    cqufs_off_t begin;
    cqufs_off_t end;
};

#ifndef CQUFS_READONLY
static int cqufs_dir_commitprog(cqufs_t *cqufs, struct cqufs_commit *commit,
        const void *buffer, cqufs_size_t size) {
    int err = cqufs_bd_prog(cqufs,
            &cqufs->pcache, &cqufs->rcache, false,
            commit->block, commit->off ,
            (const uint8_t*)buffer, size);
    if (err) {
        return err;
    }

    commit->crc = cqufs_crc(commit->crc, buffer, size);
    commit->off += size;
    return 0;
}
#endif

#ifndef CQUFS_READONLY
static int cqufs_dir_commitattr(cqufs_t *cqufs, struct cqufs_commit *commit,
        cqufs_tag_t tag, const void *buffer) {

    cqufs_size_t dsize = cqufs_tag_dsize(tag);                     /*  ����Ƿ����   */
    if (commit->off + dsize > commit->end) {
        return CQUFS_ERR_NOSPC;
    }

    cqufs_tag_t ntag = cqufs_tobe32((tag & 0x7fffffff) ^ commit->ptag);                     /*   д��ǩ  */
    int err = cqufs_dir_commitprog(cqufs, commit, &ntag, sizeof(ntag));
    if (err) {
        return err;
    }

    if (!(tag & 0x80000000)) {
        err = cqufs_dir_commitprog(cqufs, commit, buffer, dsize-sizeof(tag));                 /*  ���ڴ�   */
        if (err) {
            return err;
        }
    } else {

        const struct cqufs_diskoff *disk = buffer;                      /*  ��Ӳ��   */
        cqufs_off_t i;
        for (i = 0; i < dsize-sizeof(tag); i++) {

            uint8_t dat;
            err = cqufs_bd_read(cqufs,
                    NULL, &cqufs->rcache, dsize-sizeof(tag)-i,                     /*  �������������Ч��   */
                    disk->block, disk->off+i, &dat, 1);
            if (err) {
                return err;
            }

            err = cqufs_dir_commitprog(cqufs, commit, &dat, 1);
            if (err) {
                return err;
            }
        }
    }

    commit->ptag = tag & 0x7fffffff;
    return 0;
}
#endif

#ifndef CQUFS_READONLY
static int cqufs_dir_commitcrc(cqufs_t *cqufs, struct cqufs_commit *commit) {

    const cqufs_off_t end = cqufs_alignup(commit->off + 2*sizeof(uint32_t),                     /*  ���뵽����Ԫ   */
            cqufs->cfg->prog_size);

    cqufs_off_t off1 = 0;
    uint32_t crc1 = 0;

    /*  ˵��������CRC��ǩ������ύ��ʣ�ಿ�֣�ע������ǲ�crced�ģ����ö�ȡ������䣬��ʹ�ύ�е㸴��  */
    while (commit->off < end) {
        cqufs_off_t off = commit->off + sizeof(cqufs_tag_t);
        cqufs_off_t noff = cqufs_min(end - off, 0x3fe) + off;
        if (noff < end) {
            noff = cqufs_min(noff, end - 2*sizeof(uint32_t));
        }


        cqufs_tag_t tag = 0xffffffff;                     /*  ����һ������Ԫ��ȡ����״̬   */
        int err = cqufs_bd_read(cqufs,
                NULL, &cqufs->rcache, sizeof(tag),
                commit->block, noff, &tag, sizeof(tag));
        if (err && err != CQUFS_ERR_CORRUPT) {
            return err;
        }


        bool reset = ~cqufs_frombe32(tag) >> 31;                     /*   ����CRC��ǩ  */
        tag = CQUFS_MKTAG(CQUFS_TYPE_CRC + reset, 0x3ff, noff - off);


        uint32_t footer[2];
        footer[0] = cqufs_tobe32(tag ^ commit->ptag);
        commit->crc = cqufs_crc(commit->crc, &footer[0], sizeof(footer[0]));                     /*  д��CRC   */
        footer[1] = cqufs_tole32(commit->crc);
        err = cqufs_bd_prog(cqufs,
                &cqufs->pcache, &cqufs->rcache, false,
                commit->block, commit->off, &footer, sizeof(footer));
        if (err) {
            return err;
        }


        if (off1 == 0) {
            off1 = commit->off + sizeof(uint32_t);                     /*  ���ٷ����У����Խ�����֤   */
            crc1 = commit->crc;
        }

        commit->off += sizeof(tag)+cqufs_tag_size(tag);
        commit->ptag = tag ^ ((cqufs_tag_t)reset << 31);
        commit->crc = 0xffffffff;                      /*  ����CRCΪ��һ��"commit"   */
    }


    int err = cqufs_bd_sync(cqufs, &cqufs->pcache, &cqufs->rcache, false);                     /*  ˢ�»�����   */
    if (err) {
        return err;
    }


    cqufs_off_t off = commit->begin;                     /*  �ɹ��ύ�����checksum��ȷ��   */
    cqufs_off_t noff = off1;
    while (off < end) {
        uint32_t crc = 0xffffffff;
        cqufs_off_t i;
        for (i = off; i < noff+sizeof(uint32_t); i++) {
            /*  ˵�������д���crc�����Բ����Ϊֻ�������ύ��С��ȫƥ��Ŀ�   */
            if (i == off1 && crc != crc1) {
                return CQUFS_ERR_CORRUPT;
            }


            uint8_t dat;
            err = cqufs_bd_read(cqufs,                     /*   �û��������Ч��  */
                    NULL, &cqufs->rcache, noff+sizeof(uint32_t)-i,
                    commit->block, i, &dat, 1);
            if (err) {
                return err;
            }

            crc = cqufs_crc(crc, &dat, 1);
        }


        if (crc != 0) {
            return CQUFS_ERR_CORRUPT;                     /*  ��⵽д����   */
        }


        off = cqufs_min(end - noff, 0x3fe) + noff;                     /*  �������   */
        if (off < end) {
            off = cqufs_min(off, end - 2*sizeof(uint32_t));
        }
        noff = off + sizeof(uint32_t);
    }

    return 0;
}
#endif

#ifndef CQUFS_READONLY
static int cqufs_dir_alloc(cqufs_t *cqufs, cqufs_mdir_t *dir) {

    int i;
    for (i = 0; i < 2; i++) {
        int err = cqufs_alloc(cqufs, &dir->pair[(i+1)%2]);                     /*  ����һ��dir��(�������������д��1��   */
        if (err) {
            return err;
        }
    }


    dir->rev = 0;                     /*  0��ʾ�ڳ�ʼ�鲻�ɶ��������������   */


    int err = cqufs_bd_read(cqufs,                     /*  �����ô�����һ���飬ֻ�Ǽ�װ�޸Ŀ�������Ч��   */
            NULL, &cqufs->rcache, sizeof(dir->rev),
            dir->pair[0], 0, &dir->rev, sizeof(dir->rev));
    dir->rev = cqufs_fromle32(dir->rev);
    if (err && err != CQUFS_ERR_CORRUPT) {
        return err;
    }


    /*  ˵����Ϊ��ȷ�����������˳������µ��޶�������block_cyclesģ������   */
    if (cqufs->cfg->block_cycles > 0) {
        dir->rev = cqufs_alignup(dir->rev, ((cqufs->cfg->block_cycles+1)|1));
    }


    dir->off = sizeof(dir->rev);                     /* ����Ĭ��ֵ  */
    dir->etag = 0xffffffff;
    dir->count = 0;
    dir->tail[0] = CQUFS_BLOCK_NULL;
    dir->tail[1] = CQUFS_BLOCK_NULL;
    dir->erased = false;
    dir->split = false;


    /*   ˵����������  */
    return 0;
}
#endif

#ifndef CQUFS_READONLY
static int cqufs_dir_drop(cqufs_t *cqufs, cqufs_mdir_t *dir, cqufs_mdir_t *tail) {

    int err = cqufs_dir_getgstate(cqufs, tail, &cqufs->gdelta);                     /*  ��̬����   */
    if (err) {
        return err;
    }


    cqufs_pair_tole32(tail->tail);
    err = cqufs_dir_commit(cqufs, dir, CQUFS_MKATTRS(
            {CQUFS_MKTAG(CQUFS_TYPE_TAIL + tail->split, 0x3ff, 8), tail->tail}));
    cqufs_pair_fromle32(tail->tail);
    if (err) {
        return err;
    }

    return 0;
}
#endif

#ifndef CQUFS_READONLY
static int cqufs_dir_split(cqufs_t *cqufs,
        cqufs_mdir_t *dir, const struct cqufs_mattr *attrs, int attrcount,
        cqufs_mdir_t *source, uint16_t split, uint16_t end) {

    cqufs_mdir_t tail;
    int err = cqufs_dir_alloc(cqufs, &tail);                     /*  ����β��Ԫ���ݶ�   */
    if (err) {
        return err;
    }

    tail.split = dir->split;
    tail.tail[0] = dir->tail[0];
    tail.tail[1] = dir->tail[1];


    int res = cqufs_dir_compact(cqufs, &tail, attrs, attrcount, source, split, end);                     /*  ���ﲻ����cqufs_ok_relocation   */
    if (res < 0) {
        return res;
    }

    dir->tail[0] = tail.pair[0];
    dir->tail[1] = tail.pair[1];
    dir->split = true;


    if (cqufs_pair_cmp(dir->pair, cqufs->root) == 0 && split == 0) {                     /*  �����Ҫ�����¸�Ŀ¼   */
        cqufs->root[0] = tail.pair[0];
        cqufs->root[1] = tail.pair[1];
    }

    return 0;
}
#endif

#ifndef CQUFS_READONLY
static int cqufs_dir_commit_size(void *p, cqufs_tag_t tag, const void *buffer) {
    cqufs_size_t *size = p;
    (void)buffer;

    *size += cqufs_tag_dsize(tag);
    return 0;
}
#endif

#ifndef CQUFS_READONLY
struct cqufs_dir_commit_commit {
    cqufs_t *cqufs;
    struct cqufs_commit *commit;
};
#endif

#ifndef CQUFS_READONLY
static int cqufs_dir_commit_commit(void *p, cqufs_tag_t tag, const void *buffer) {
    struct cqufs_dir_commit_commit *commit = p;
    return cqufs_dir_commitattr(commit->cqufs, commit->commit, tag, buffer);
}
#endif

#ifndef CQUFS_READONLY
static bool cqufs_dir_needsrelocation(cqufs_t *cqufs, cqufs_mdir_t *dir) {

    /*  ˵��������޶�����== n * block_cycles��Ӧ��ǿ���ض�λ��ʵ����ʹ����(block_cycles+1)|1  */
    return (cqufs->cfg->block_cycles > 0
            && ((dir->rev + 1) % ((cqufs->cfg->block_cycles+1)|1) == 0));
}
#endif

#ifndef CQUFS_READONLY
static int cqufs_dir_compact(cqufs_t *cqufs,
        cqufs_mdir_t *dir, const struct cqufs_mattr *attrs, int attrcount,
        cqufs_mdir_t *source, uint16_t begin, uint16_t end) {

    bool relocated = false;
    bool tired = cqufs_dir_needsrelocation(cqufs, dir);                     /*  ����һЩ״̬��case���ǻ���   */


    dir->rev += 1;                     /*  �����޶�����   */


    /*  ˵������Ҫ��Ǩ�ƹ������������¶�λ�飬����ܻᵼ�����ʧ��״̬   */
#ifdef CQUFS_MIGRATE
    if (cqufs->cqufs1) {
        tired = false;
    }
#endif

    if (tired && cqufs_pair_cmp(dir->pair, (const cqufs_block_t[2]){0, 1}) != 0) {
        goto relocate;
    }

    /*  ˵������ʼѭ���ύѹ������   */
    while (true) {
        {

            struct cqufs_commit commit = {                     /*  �����ύ״̬   */
                .block = dir->pair[1],
                .off = 0,
                .ptag = 0xffffffff,
                .crc = 0xffffffff,

                .begin = 0,
                .end = (cqufs->cfg->metadata_max ?
                    cqufs->cfg->metadata_max : cqufs->cfg->block_size) - 8,
            };


            int err = cqufs_bd_erase(cqufs, dir->pair[1]);                     /*  ����Ҫд��Ŀ�   */
            if (err) {
                if (err == CQUFS_ERR_CORRUPT) {
                    goto relocate;
                }
                return err;
            }


            dir->rev = cqufs_tole32(dir->rev);                             /*  д��ͷ�ļ�   */
            err = cqufs_dir_commitprog(cqufs, &commit,
                    &dir->rev, sizeof(dir->rev));
            dir->rev = cqufs_fromle32(dir->rev);
            if (err) {
                if (err == CQUFS_ERR_CORRUPT) {
                    goto relocate;
                }
                return err;
            }


            err = cqufs_dir_traverse(cqufs,                                    /*  ����Ŀ¼�����д������Ψһ�ı�ǩ   */
                    source, 0, 0xffffffff, attrs, attrcount,
                    CQUFS_MKTAG(0x400, 0x3ff, 0),
                    CQUFS_MKTAG(CQUFS_TYPE_NAME, 0, 0),
                    begin, end, -begin,
                    cqufs_dir_commit_commit, &(struct cqufs_dir_commit_commit){
                        cqufs, &commit});
            if (err) {
                if (err == CQUFS_ERR_CORRUPT) {
                    goto relocate;
                }
                return err;
            }


            if (!cqufs_pair_isnull(dir->tail)) {                           /*  �ύβ�������һ�δ�С���   */
                cqufs_pair_tole32(dir->tail);
                err = cqufs_dir_commitattr(cqufs, &commit,
                        CQUFS_MKTAG(CQUFS_TYPE_TAIL + dir->split, 0x3ff, 8),
                        dir->tail);
                cqufs_pair_fromle32(dir->tail);
                if (err) {
                    if (err == CQUFS_ERR_CORRUPT) {
                        goto relocate;
                    }
                    return err;
                }
            }


            cqufs_gstate_t delta = {0};                     /* ��gstate   */
            if (!relocated) {
                cqufs_gstate_xor(&delta, &cqufs->gdisk);
                cqufs_gstate_xor(&delta, &cqufs->gstate);
            }
            cqufs_gstate_xor(&delta, &cqufs->gdelta);
            delta.tag &= ~CQUFS_MKTAG(0, 0, 0x3ff);

            err = cqufs_dir_getgstate(cqufs, dir, &delta);
            if (err) {
                return err;
            }

            if (!cqufs_gstate_iszero(&delta)) {
                cqufs_gstate_tole32(&delta);
                err = cqufs_dir_commitattr(cqufs, &commit,
                        CQUFS_MKTAG(CQUFS_TYPE_MOVESTATE, 0x3ff,
                            sizeof(delta)), &delta);
                if (err) {
                    if (err == CQUFS_ERR_CORRUPT) {
                        goto relocate;
                    }
                    return err;
                }
            }


            err = cqufs_dir_commitcrc(cqufs, &commit);                     /*  ʹ��CRC����ύ   */
            if (err) {
                if (err == CQUFS_ERR_CORRUPT) {
                    goto relocate;
                }
                return err;
            }


            CQUFS_ASSERT(commit.off % cqufs->cfg->prog_size == 0);                     /*  �ɹ���ѹ��������dir��ָʾ���  */
            cqufs_pair_swap(dir->pair);
            dir->count = end - begin;
            dir->off = commit.off;
            dir->etag = commit.ptag;

            cqufs->gdelta = (cqufs_gstate_t){0};                     /*   ����gstate  */
            if (!relocated) {
                cqufs->gdisk = cqufs->gstate;
            }
        }
        break;

relocate:

        relocated = true;                     /*  �ύ���𻵣�ɾ�����沢׼�����¶�λ��   */
        cqufs_cache_drop(cqufs, &cqufs->pcache);
        if (!tired) {
            CQUFS_DEBUG("Bad block at 0x%"PRIx32, dir->pair[1]);
        }


        if (cqufs_pair_cmp(dir->pair, (const cqufs_block_t[2]){0, 1}) == 0) {                     /*  �������¶�λ�����飬�ļ�ϵͳ���ڶ���   */
            CQUFS_WARN("Superblock 0x%"PRIx32" has become unwritable",
                    dir->pair[1]);
            return CQUFS_ERR_NOSPC;
        }


        int err = cqufs_alloc(cqufs, &dir->pair[1]);                     /*  ����һ���pair   */
        if (err && (err != CQUFS_ERR_NOSPC || !tired)) {
            return err;
        }

        tired = false;
        continue;
    }

    return relocated ? CQUFS_OK_RELOCATED : 0;
}
#endif

#ifndef CQUFS_READONLY
static int cqufs_dir_splittingcompact(cqufs_t *cqufs, cqufs_mdir_t *dir,
        const struct cqufs_mattr *attrs, int attrcount,
        cqufs_mdir_t *source, uint16_t begin, uint16_t end) {
    while (true) {

        /*  ˵�����ҵ���һ�β�ֵĴ�С������ͨ����������ʵ�֣�ֱ����֤Ԫ�����ܹ�ƥ��Ϊֹ   */
        cqufs_size_t split = begin;
        while (end - split > 1) {
            cqufs_size_t size = 0;
            int err = cqufs_dir_traverse(cqufs,
                    source, 0, 0xffffffff, attrs, attrcount,
                    CQUFS_MKTAG(0x400, 0x3ff, 0),
                    CQUFS_MKTAG(CQUFS_TYPE_NAME, 0, 0),
                    split, end, -split,
                    cqufs_dir_commit_size, &size);
            if (err) {
                return err;
            }


            if (end - split < 0xff
                    && size <= cqufs_min(cqufs->cfg->block_size - 36,
                        cqufs_alignup(
                            (cqufs->cfg->metadata_max
                                ? cqufs->cfg->metadata_max
                                : cqufs->cfg->block_size)/2,
                            cqufs->cfg->prog_size))) {
                break;
            }

            split = split + ((end - split) / 2);
        }

        if (split == begin) {                     /*  ����Ҫ�ָ�   */

            break;
        }


        int err = cqufs_dir_split(cqufs, dir, attrs, attrcount,                     /*  ���ѳ�����Ԫ���ݶԲ�����   */
                source, split, end);
        if (err && err != CQUFS_ERR_NOSPC) {
            return err;
        }

        if (err) {                     /*  ���ܷ���һ���µĿ飬����ѹ�������½�   */

            CQUFS_WARN("Unable to split {0x%"PRIx32", 0x%"PRIx32"}",
                    dir->pair[0], dir->pair[1]);
            break;
        } else {
            end = split;
        }
    }

    if (cqufs_dir_needsrelocation(cqufs, dir)
            && cqufs_pair_cmp(dir->pair, (const cqufs_block_t[2]){0, 1}) == 0) {

        cqufs_ssize_t size = cqufs_fs_rawsize(cqufs);                     /*  д�볬��̫��   */
        if (size < 0) {
            return size;
        }


        if ((cqufs_size_t)size < cqufs->cfg->block_count/2) {                     /*  ��������   */
            CQUFS_DEBUG("Expanding superblock at rev %"PRIu32, dir->rev);
            int err = cqufs_dir_split(cqufs, dir, attrs, attrcount,
                    source, begin, end);
            if (err && err != CQUFS_ERR_NOSPC) {
                return err;
            }

            if (err) {
                CQUFS_WARN("Unable to expand superblock");
            } else {
                end = begin;
            }
        }
    }

    return cqufs_dir_compact(cqufs, dir, attrs, attrcount, source, begin, end);
}
#endif

#ifndef CQUFS_READONLY
static int cqufs_dir_relocatingcommit(cqufs_t *cqufs, cqufs_mdir_t *dir,
        const cqufs_block_t pair[2],
        const struct cqufs_mattr *attrs, int attrcount,
        cqufs_mdir_t *pdir) {
    int state = 0;

    bool hasdelete = false;                     /*  �������Ŀ¼   */
    int i;
    for (i = 0; i < attrcount; i++) {
        if (cqufs_tag_type3(attrs[i].tag) == CQUFS_TYPE_CREATE) {
            dir->count += 1;
        } else if (cqufs_tag_type3(attrs[i].tag) == CQUFS_TYPE_DELETE) {
            CQUFS_ASSERT(dir->count > 0);
            dir->count -= 1;
            hasdelete = true;
        } else if (cqufs_tag_type1(attrs[i].tag) == CQUFS_TYPE_TAIL) {
            dir->tail[0] = ((cqufs_block_t*)attrs[i].buffer)[0];
            dir->tail[1] = ((cqufs_block_t*)attrs[i].buffer)[1];
            dir->split = (cqufs_tag_chunk(attrs[i].tag) & 1);
            cqufs_pair_fromle32(dir->tail);
        }
    }

    if (hasdelete && dir->count == 0) {                     /*   �Ƿ�Ӧ��ɾ��Ŀ¼��   */
        CQUFS_ASSERT(pdir);
        int err = cqufs_fs_pred(cqufs, dir->pair, pdir);
        if (err && err != CQUFS_ERR_NOENT) {
            return err;
        }

        if (err != CQUFS_ERR_NOENT && pdir->split) {
            state = CQUFS_OK_DROPPED;
            goto fixmlist;
        }
    }

    if (dir->erased) {
        struct cqufs_commit commit = {                     /*  �����ύ   */
            .block = dir->pair[0],
            .off = dir->off,
            .ptag = dir->etag,
            .crc = 0xffffffff,

            .begin = dir->off,
            .end = (cqufs->cfg->metadata_max ?
                cqufs->cfg->metadata_max : cqufs->cfg->block_size) - 8,
        };

        cqufs_pair_tole32(dir->tail);                     /*  ������Ҫд����������   */
        int err = cqufs_dir_traverse(cqufs,
                dir, dir->off, dir->etag, attrs, attrcount,
                0, 0, 0, 0, 0,
                cqufs_dir_commit_commit, &(struct cqufs_dir_commit_commit){
                    cqufs, &commit});
        cqufs_pair_fromle32(dir->tail);
        if (err) {
            if (err == CQUFS_ERR_NOSPC || err == CQUFS_ERR_CORRUPT) {
                goto compact;
            }
            return err;
        }

        cqufs_gstate_t delta = {0};                     /* �ύ�κ�ȫ�ֲ���  */
        cqufs_gstate_xor(&delta, &cqufs->gstate);
        cqufs_gstate_xor(&delta, &cqufs->gdisk);
        cqufs_gstate_xor(&delta, &cqufs->gdelta);
        delta.tag &= ~CQUFS_MKTAG(0, 0, 0x3ff);
        if (!cqufs_gstate_iszero(&delta)) {
            err = cqufs_dir_getgstate(cqufs, dir, &delta);
            if (err) {
                return err;
            }

            cqufs_gstate_tole32(&delta);
            err = cqufs_dir_commitattr(cqufs, &commit,
                    CQUFS_MKTAG(CQUFS_TYPE_MOVESTATE, 0x3ff,
                        sizeof(delta)), &delta);
            if (err) {
                if (err == CQUFS_ERR_NOSPC || err == CQUFS_ERR_CORRUPT) {
                    goto compact;
                }
                return err;
            }
        }

        err = cqufs_dir_commitcrc(cqufs, &commit);                     /*   ���CRC���ύ  */
        if (err) {
            if (err == CQUFS_ERR_NOSPC || err == CQUFS_ERR_CORRUPT) {
                goto compact;
            }
            return err;
        }

        CQUFS_ASSERT(commit.off % cqufs->cfg->prog_size == 0);                     /*  �ɹ��ύ������dir������gstate   */
        dir->off = commit.off;
        dir->etag = commit.ptag;
        cqufs->gdisk = cqufs->gstate;
        cqufs->gdelta = (cqufs_gstate_t){0};

        goto fixmlist;
    }

compact:
    cqufs_cache_drop(cqufs, &cqufs->pcache);                     /*  ����ѹ��   */

    state = cqufs_dir_splittingcompact(cqufs, dir, attrs, attrcount,
            dir, 0, dir->count);
    if (state < 0) {
        return state;
    }

    goto fixmlist;

fixmlist:;
    cqufs_block_t oldpair[2] = {pair[0], pair[1]};
    struct cqufs_mlist *d;
    for (d = cqufs->mlist; d; d = d->next) {
        if (cqufs_pair_cmp(d->m.pair, oldpair) == 0) {
            d->m = *dir;
            if (d->m.pair != pair) {
                int i;
                for (i = 0; i < attrcount; i++) {
                    if (cqufs_tag_type3(attrs[i].tag) == CQUFS_TYPE_DELETE &&
                            d->id == cqufs_tag_id(attrs[i].tag)) {
                        d->m.pair[0] = CQUFS_BLOCK_NULL;
                        d->m.pair[1] = CQUFS_BLOCK_NULL;
                    } else if (cqufs_tag_type3(attrs[i].tag) == CQUFS_TYPE_DELETE &&
                            d->id > cqufs_tag_id(attrs[i].tag)) {
                        d->id -= 1;
                        if (d->type == CQUFS_TYPE_DIR) {
                            ((cqufs_dir_t*)d)->pos -= 1;
                        }
                    } else if (cqufs_tag_type3(attrs[i].tag) == CQUFS_TYPE_CREATE &&
                            d->id >= cqufs_tag_id(attrs[i].tag)) {
                        d->id += 1;
                        if (d->type == CQUFS_TYPE_DIR) {
                            ((cqufs_dir_t*)d)->pos += 1;
                        }
                    }
                }
            }

            while (d->id >= d->m.count && d->m.split) {
                d->id -= d->m.count;
                int err = cqufs_dir_fetch(cqufs, &d->m, d->m.tail);
                if (err) {
                    return err;
                }
            }
        }
    }

    return state;
}
#endif

#ifndef CQUFS_READONLY
static int cqufs_dir_orphaningcommit(cqufs_t *cqufs, cqufs_mdir_t *dir,
        const struct cqufs_mattr *attrs, int attrcount) {
    cqufs_file_t *f;
    for (f = (cqufs_file_t*)cqufs->mlist; f; f = f->next) {
        if (dir != &f->m && cqufs_pair_cmp(f->m.pair, dir->pair) == 0 &&
                f->type == CQUFS_TYPE_REG && (f->flags & CQUFS_F_INLINE) &&
                f->ctz.size > cqufs->cfg->cache_size) {
            int err = cqufs_file_outline(cqufs, f);
            if (err) {
                return err;
            }

            err = cqufs_file_flush(cqufs, f);
            if (err) {
                return err;
            }
        }
    }

    cqufs_block_t lpair[2] = {dir->pair[0], dir->pair[1]};
    cqufs_mdir_t ldir = *dir;
    cqufs_mdir_t pdir;
    int state = cqufs_dir_relocatingcommit(cqufs, &ldir, dir->pair,
            attrs, attrcount, &pdir);
    if (state < 0) {
        return state;
    }

    if (cqufs_pair_cmp(dir->pair, lpair) == 0) {
        *dir = ldir;
    }


    if (state == CQUFS_OK_DROPPED) {                           /*  ��Ҫɾ��   */
        // steal state
        int err = cqufs_dir_getgstate(cqufs, dir, &cqufs->gdelta);
        if (err) {
            return err;
        }

        lpair[0] = pdir.pair[0];                                                  /*  ���ܴ����ݹ�ɾ��   */
        lpair[1] = pdir.pair[1];
        cqufs_pair_tole32(dir->tail);
        state = cqufs_dir_relocatingcommit(cqufs, &pdir, lpair, CQUFS_MKATTRS(
                    {CQUFS_MKTAG(CQUFS_TYPE_TAIL + dir->split, 0x3ff, 8),
                        dir->tail}),
                NULL);
        cqufs_pair_fromle32(dir->tail);
        if (state < 0) {
            return state;
        }

        ldir = pdir;
    }

    bool orphans = false;
    while (state == CQUFS_OK_RELOCATED) {                     /* ��Ҫ���¶�λ    */
        CQUFS_DEBUG("Relocating {0x%"PRIx32", 0x%"PRIx32"} "
                    "-> {0x%"PRIx32", 0x%"PRIx32"}",
                lpair[0], lpair[1], ldir.pair[0], ldir.pair[1]);
        state = 0;

        if (cqufs_pair_cmp(lpair, cqufs->root) == 0) {                     /*  �����ڲ���Ŀ¼   */
            cqufs->root[0] = ldir.pair[0];
            cqufs->root[1] = ldir.pair[1];
        }

        struct cqufs_mlist *d;
        for (d = cqufs->mlist; d; d = d->next) {                     /*  �����ڲ����ٵ�dirs   */
            if (cqufs_pair_cmp(lpair, d->m.pair) == 0) {
                d->m.pair[0] = ldir.pair[0];
                d->m.pair[1] = ldir.pair[1];
            }

            if (d->type == CQUFS_TYPE_DIR &&
                    cqufs_pair_cmp(lpair, ((cqufs_dir_t*)d)->head) == 0) {
                ((cqufs_dir_t*)d)->head[0] = ldir.pair[0];
                ((cqufs_dir_t*)d)->head[1] = ldir.pair[1];
            }
        }

        cqufs_stag_t tag = cqufs_fs_parent(cqufs, lpair, &pdir);                     /*  �ҵ����ڵ�   */
        if (tag < 0 && tag != CQUFS_ERR_NOENT) {
            return tag;
        }

        bool hasparent = (tag != CQUFS_ERR_NOENT);
        if (tag != CQUFS_ERR_NOENT) {
            int err = cqufs_fs_preporphans(cqufs, +1);
            if (err) {
                return err;
            }

            uint16_t moveid = 0x3ff;
            if (cqufs_gstate_hasmovehere(&cqufs->gstate, pdir.pair)) {
                moveid = cqufs_tag_id(cqufs->gstate.tag);
                CQUFS_DEBUG("Fixing move while relocating "
                        "{0x%"PRIx32", 0x%"PRIx32"} 0x%"PRIx16"\n",
                        pdir.pair[0], pdir.pair[1], moveid);
                cqufs_fs_prepmove(cqufs, 0x3ff, NULL);
                if (moveid < cqufs_tag_id(tag)) {
                    tag -= CQUFS_MKTAG(0, 1, 0);
                }
            }

            cqufs_block_t ppair[2] = {pdir.pair[0], pdir.pair[1]};
            cqufs_pair_tole32(ldir.pair);
            state = cqufs_dir_relocatingcommit(cqufs, &pdir, ppair, CQUFS_MKATTRS(
                        {CQUFS_MKTAG_IF(moveid != 0x3ff,
                            CQUFS_TYPE_DELETE, moveid, 0), NULL},
                        {tag, ldir.pair}),
                    NULL);
            cqufs_pair_fromle32(ldir.pair);
            if (state < 0) {
                return state;
            }

            if (state == CQUFS_OK_RELOCATED) {
                lpair[0] = ppair[0];
                lpair[1] = ppair[1];
                ldir = pdir;
                orphans = true;
                continue;
            }
        }

        int err = cqufs_fs_pred(cqufs, lpair, &pdir);                     /*   �ҵ�pred  */
        if (err && err != CQUFS_ERR_NOENT) {
            return err;
        }
        CQUFS_ASSERT(!(hasparent && err == CQUFS_ERR_NOENT));

        if (err != CQUFS_ERR_NOENT) {                     /*  ����Ҳ���dir����һ�����µ�   */
            if (cqufs_gstate_hasorphans(&cqufs->gstate)) {
                // next step, clean up orphans
                err = cqufs_fs_preporphans(cqufs, -hasparent);
                if (err) {
                    return err;
                }
            }
            uint16_t moveid = 0x3ff;
            if (cqufs_gstate_hasmovehere(&cqufs->gstate, pdir.pair)) {
                moveid = cqufs_tag_id(cqufs->gstate.tag);
                CQUFS_DEBUG("Fixing move while relocating "
                        "{0x%"PRIx32", 0x%"PRIx32"} 0x%"PRIx16"\n",
                        pdir.pair[0], pdir.pair[1], moveid);
                cqufs_fs_prepmove(cqufs, 0x3ff, NULL);
            }

            lpair[0] = pdir.pair[0];
            lpair[1] = pdir.pair[1];
            cqufs_pair_tole32(ldir.pair);
            state = cqufs_dir_relocatingcommit(cqufs, &pdir, lpair, CQUFS_MKATTRS(                     /*  �滻����pair��Ҫô���������ͬ����Ҫô��ͬ������   */
                        {CQUFS_MKTAG_IF(moveid != 0x3ff,
                            CQUFS_TYPE_DELETE, moveid, 0), NULL},
                        {CQUFS_MKTAG(CQUFS_TYPE_TAIL + pdir.split, 0x3ff, 8),
                            ldir.pair}),
                    NULL);
            cqufs_pair_fromle32(ldir.pair);
            if (state < 0) {
                return state;
            }

            ldir = pdir;
        }
    }

    return orphans ? CQUFS_OK_ORPHANED : 0;
}
#endif

#ifndef CQUFS_READONLY
static int cqufs_dir_commit(cqufs_t *cqufs, cqufs_mdir_t *dir,
        const struct cqufs_mattr *attrs, int attrcount) {
    int orphans = cqufs_dir_orphaningcommit(cqufs, dir, attrs, attrcount);
    if (orphans < 0) {
        return orphans;
    }

    if (orphans) {
        int err = cqufs_fs_deorphan(cqufs, false);
        if (err) {
            return err;
        }
    }

    return 0;
}
#endif

/*********************************************************************************************************
  ����Ŀ¼����
*********************************************************************************************************/
#ifndef CQUFS_READONLY
static int cqufs_rawmkdir(cqufs_t *cqufs, const char *path) {

    int err = cqufs_fs_forceconsistency(cqufs);                     /*  deorphan�����û�У���ͨ��������Ҫһ��  */
    if (err) {
        return err;
    }

    struct cqufs_mlist cwd;
    cwd.next = cqufs->mlist;
    uint16_t id;
    err = cqufs_dir_find(cqufs, &cwd.m, &path, &id);
    if (!(err == CQUFS_ERR_NOENT && id != 0x3ff)) {
        return (err < 0) ? err : CQUFS_ERR_EXIST;
    }

    cqufs_size_t nlen = strlen(path);                     /*  ��������Ƿ�ƥ��   */
    if (nlen > cqufs->name_max) {
        return CQUFS_ERR_NAMETOOLONG;
    }

    cqufs_alloc_ack(cqufs);                     /*  �½�Ŀ¼   */
    cqufs_mdir_t dir;
    err = cqufs_dir_alloc(cqufs, &dir);
    if (err) {
        return err;
    }

    cqufs_mdir_t pred = cwd.m;                     /*  �����б��ĩβ   */
    while (pred.split) {
        err = cqufs_dir_fetch(cqufs, &pred, pred.tail);
        if (err) {
            return err;
        }
    }

    cqufs_pair_tole32(pred.tail);                 /*  ����dir   */
    err = cqufs_dir_commit(cqufs, &dir, CQUFS_MKATTRS(
            {CQUFS_MKTAG(CQUFS_TYPE_SOFTTAIL, 0x3ff, 8), pred.tail}));
    cqufs_pair_fromle32(pred.tail);
    if (err) {
        return err;
    }

    if (cwd.m.split) {                     /*  ��ǰ�鲻�����б�   */
        err = cqufs_fs_preporphans(cqufs, +1);
        if (err) {
            return err;
        }

        cwd.type = 0;
        cwd.id = 0;
        cqufs->mlist = &cwd;

        cqufs_pair_tole32(dir.pair);
        err = cqufs_dir_commit(cqufs, &pred, CQUFS_MKATTRS(
                {CQUFS_MKTAG(CQUFS_TYPE_SOFTTAIL, 0x3ff, 8), dir.pair}));
        cqufs_pair_fromle32(dir.pair);
        if (err) {
            cqufs->mlist = cwd.next;
            return err;
        }

        cqufs->mlist = cwd.next;
        err = cqufs_fs_preporphans(cqufs, -1);
        if (err) {
            return err;
        }
    }

    cqufs_pair_tole32(dir.pair);                     /*  ���븸��   */
    err = cqufs_dir_commit(cqufs, &cwd.m, CQUFS_MKATTRS(
            {CQUFS_MKTAG(CQUFS_TYPE_CREATE, id, 0), NULL},
            {CQUFS_MKTAG(CQUFS_TYPE_DIR, id, nlen), path},
            {CQUFS_MKTAG(CQUFS_TYPE_DIRSTRUCT, id, 8), dir.pair},
            {CQUFS_MKTAG_IF(!cwd.m.split,
                CQUFS_TYPE_SOFTTAIL, 0x3ff, 8), dir.pair}));
    cqufs_pair_fromle32(dir.pair);
    if (err) {
        return err;
    }

    return 0;
}
#endif

static int cqufs_dir_rawopen(cqufs_t *cqufs, cqufs_dir_t *dir, const char *path) {
    cqufs_stag_t tag = cqufs_dir_find(cqufs, &dir->m, &path, NULL);
    if (tag < 0) {
        return tag;
    }

    if (cqufs_tag_type3(tag) != CQUFS_TYPE_DIR) {
        return CQUFS_ERR_NOTDIR;
    }

    cqufs_block_t pair[2];
    if (cqufs_tag_id(tag) == 0x3ff) {
        pair[0] = cqufs->root[0];                     /*  �����Ŀ¼   */
        pair[1] = cqufs->root[1];
    } else {
        cqufs_stag_t res = cqufs_dir_get(cqufs, &dir->m, CQUFS_MKTAG(0x700, 0x3ff, 0),                     /*  �Ӹ�Ŀ¼��ȡdir pair  */
                CQUFS_MKTAG(CQUFS_TYPE_STRUCT, cqufs_tag_id(tag), 8), pair);
        if (res < 0) {
            return res;
        }
        cqufs_pair_fromle32(pair);
    }

    int err = cqufs_dir_fetch(cqufs, &dir->m, pair);
    if (err) {
        return err;
    }

    dir->head[0] = dir->m.pair[0];                     /*  ������Ŀ   */
    dir->head[1] = dir->m.pair[1];
    dir->id = 0;
    dir->pos = 0;

    dir->type = CQUFS_TYPE_DIR;                     /*   ��ӵ�Ԫ�����б�  */
    cqufs_mlist_append(cqufs, (struct cqufs_mlist *)dir);

    return 0;
}

static int cqufs_dir_rawclose(cqufs_t *cqufs, cqufs_dir_t *dir) {
    cqufs_mlist_remove(cqufs, (struct cqufs_mlist *)dir);                     /*   ��Ԫ�����б���ɾ��  */

    return 0;
}

static int cqufs_dir_rawread(cqufs_t *cqufs, cqufs_dir_t *dir, struct cqufs_info *info) {
    memset(info, 0, sizeof(*info));
    if (dir->pos == 0) {                     /*  �����ƫ��"."��".."   */
        info->type = CQUFS_TYPE_DIR;
        strcpy(info->name, ".");
        dir->pos += 1;
        return true;
    } else if (dir->pos == 1) {
        info->type = CQUFS_TYPE_DIR;
        strcpy(info->name, "..");
        dir->pos += 1;
        return true;
    }

    while (true) {
        if (dir->id == dir->m.count) {
            if (!dir->m.split) {
                return false;
            }

            int err = cqufs_dir_fetch(cqufs, &dir->m, dir->m.tail);
            if (err) {
                return err;
            }

            dir->id = 0;
        }

        int err = cqufs_dir_getinfo(cqufs, &dir->m, dir->id, info);
        if (err && err != CQUFS_ERR_NOENT) {
            return err;
        }

        dir->id += 1;
        if (err != CQUFS_ERR_NOENT) {
            break;
        }
    }

    dir->pos += 1;
    return true;
}

static int cqufs_dir_rawseek(cqufs_t *cqufs, cqufs_dir_t *dir, cqufs_off_t off) {
    int err = cqufs_dir_rawrewind(cqufs, dir);
    if (err) {
        return err;
    }

    dir->pos = cqufs_min(2, off);
    off -= dir->pos;

    dir->id = (off > 0 && cqufs_pair_cmp(dir->head, cqufs->root) == 0);                     /*   ������������Ŀ  */

    while (off > 0) {
        int diff = cqufs_min(dir->m.count - dir->id, off);
        dir->id += diff;
        dir->pos += diff;
        off -= diff;

        if (dir->id == dir->m.count) {
            if (!dir->m.split) {
                return CQUFS_ERR_INVAL;
            }

            err = cqufs_dir_fetch(cqufs, &dir->m, dir->m.tail);
            if (err) {
                return err;
            }

            dir->id = 0;
        }
    }

    return 0;
}

static cqufs_soff_t cqufs_dir_rawtell(cqufs_t *cqufs, cqufs_dir_t *dir) {
    (void)cqufs;
    return dir->pos;
}

static int cqufs_dir_rawrewind(cqufs_t *cqufs, cqufs_dir_t *dir) {
    int err = cqufs_dir_fetch(cqufs, &dir->m, dir->head);                     /*  ���¼���ͷĿ¼  */
    if (err) {
        return err;
    }

    dir->id = 0;
    dir->pos = 0;
    return 0;
}

/*********************************************************************************************************
  �ļ������б����
*********************************************************************************************************/
static int cqufs_ctz_index(cqufs_t *cqufs, cqufs_off_t *off) {
    cqufs_off_t size = *off;
    cqufs_off_t b = cqufs->cfg->block_size - 2*4;
    cqufs_off_t i = size / b;
    if (i == 0) {
        return 0;
    }

    i = (size - 4*(cqufs_popc(i-1)+2)) / b;
    *off = size - b*i - 4*cqufs_popc(i);
    return i;
}

static int cqufs_ctz_find(cqufs_t *cqufs,
        const cqufs_cache_t *pcache, cqufs_cache_t *rcache,
        cqufs_block_t head, cqufs_size_t size,
        cqufs_size_t pos, cqufs_block_t *block, cqufs_off_t *off) {
    if (size == 0) {
        *block = CQUFS_BLOCK_NULL;
        *off = 0;
        return 0;
    }

    cqufs_off_t current = cqufs_ctz_index(cqufs, &(cqufs_off_t){size-1});
    cqufs_off_t target = cqufs_ctz_index(cqufs, &pos);

    while (current > target) {
        cqufs_size_t skip = cqufs_min(
                cqufs_npw2(current-target+1) - 1,
                cqufs_ctz(current));

        int err = cqufs_bd_read(cqufs,
                pcache, rcache, sizeof(head),
                head, 4*skip, &head, sizeof(head));
        head = cqufs_fromle32(head);
        if (err) {
            return err;
        }

        current -= 1 << skip;
    }

    *block = head;
    *off = pos;
    return 0;
}

#ifndef CQUFS_READONLY
static int cqufs_ctz_extend(cqufs_t *cqufs,
        cqufs_cache_t *pcache, cqufs_cache_t *rcache,
        cqufs_block_t head, cqufs_size_t size,
        cqufs_block_t *block, cqufs_off_t *off) {
    while (true) {
        cqufs_block_t nblock;                     /*  ����ץȡһ��block   */
        int err = cqufs_alloc(cqufs, &nblock);
        if (err) {
            return err;
        }

        {
            err = cqufs_bd_erase(cqufs, nblock);
            if (err) {
                if (err == CQUFS_ERR_CORRUPT) {
                    goto relocate;
                }
                return err;
            }

            if (size == 0) {
                *block = nblock;
                *off = 0;
                return 0;
            }

            cqufs_size_t noff = size - 1;
            cqufs_off_t index = cqufs_ctz_index(cqufs, &noff);
            noff = noff + 1;

            if (noff != cqufs->cfg->block_size) {                     /*  �������һ���飬������ǲ�������  */
                cqufs_off_t i;
                for (i = 0; i < noff; i++) {
                    uint8_t data;
                    err = cqufs_bd_read(cqufs,
                            NULL, rcache, noff-i,
                            head, i, &data, 1);
                    if (err) {
                        return err;
                    }

                    err = cqufs_bd_prog(cqufs,
                            pcache, rcache, true,
                            nblock, i, &data, 1);
                    if (err) {
                        if (err == CQUFS_ERR_CORRUPT) {
                            goto relocate;
                        }
                        return err;
                    }
                }

                *block = nblock;
                *off = noff;
                return 0;
            }

            index += 1;                     /*  ��ӿ�   */
            cqufs_size_t skips = cqufs_ctz(index) + 1;
            cqufs_block_t nhead = head;
            cqufs_off_t i;
            for (i = 0; i < skips; i++) {
                nhead = cqufs_tole32(nhead);
                err = cqufs_bd_prog(cqufs, pcache, rcache, true,
                        nblock, 4*i, &nhead, 4);
                nhead = cqufs_fromle32(nhead);
                if (err) {
                    if (err == CQUFS_ERR_CORRUPT) {
                        goto relocate;
                    }
                    return err;
                }

                if (i != skips-1) {
                    err = cqufs_bd_read(cqufs,
                            NULL, rcache, sizeof(nhead),
                            nhead, 4*i, &nhead, sizeof(nhead));
                    nhead = cqufs_fromle32(nhead);
                    if (err) {
                        return err;
                    }
                }
            }

            *block = nblock;
            *off = 4*skips;
            return 0;
        }

relocate:
        CQUFS_DEBUG("Bad block at 0x%"PRIx32, nblock);
        cqufs_cache_drop(cqufs, pcache);                     /*  �����沢�����µĿ�   */
    }
}
#endif

static int cqufs_ctz_traverse(cqufs_t *cqufs,
        const cqufs_cache_t *pcache, cqufs_cache_t *rcache,
        cqufs_block_t head, cqufs_size_t size,
        int (*cb)(void*, cqufs_block_t), void *data) {
    if (size == 0) {
        return 0;
    }

    cqufs_off_t index = cqufs_ctz_index(cqufs, &(cqufs_off_t){size-1});

    while (true) {
        int err = cb(data, head);
        if (err) {
            return err;
        }

        if (index == 0) {
            return 0;
        }

        cqufs_block_t heads[2];
        int count = 2 - (index & 1);
        err = cqufs_bd_read(cqufs,
                pcache, rcache, count*sizeof(head),
                head, 0, &heads, count*sizeof(head));
        heads[0] = cqufs_fromle32(heads[0]);
        heads[1] = cqufs_fromle32(heads[1]);
        if (err) {
            return err;
        }
        int i;
        for (i = 0; i < count-1; i++) {
            err = cb(data, heads[i]);
            if (err) {
                return err;
            }
        }

        head = heads[count-1];
        index -= count;
    }
}

/*********************************************************************************************************
  �����ļ�����
*********************************************************************************************************/
static int cqufs_file_rawopencfg(cqufs_t *cqufs, cqufs_file_t *file,
        const char *path, int flags,
        const struct cqufs_file_config *cfg) {
#ifndef CQUFS_READONLY
    if ((flags & CQUFS_O_WRONLY) == CQUFS_O_WRONLY) {                     /*  deorphan�����û�У���ͨ��������Ҫһ��  */
        int err = cqufs_fs_forceconsistency(cqufs);
        if (err) {
            return err;
        }
    }
#else
    CQUFS_ASSERT((flags & CQUFS_O_RDONLY) == CQUFS_O_RDONLY);
#endif

    int err;                     /*  ���ü򵥵��ļ�ϸ��   */
    file->cfg = cfg;
    file->flags = flags;
    file->pos = 0;
    file->off = 0;
    file->cache.buffer = NULL;

    cqufs_stag_t tag = cqufs_dir_find(cqufs, &file->m, &path, &file->id);                     /*  Ϊ�ļ����䲻���ڵ���Ŀ   */
    if (tag < 0 && !(tag == CQUFS_ERR_NOENT && file->id != 0x3ff)) {
        err = tag;
        goto cleanup;
    }

    file->type = CQUFS_TYPE_REG;                     /*  ��ȡid����ӵ�Ԫ�����б��Բ�׽���µı仯   */
    cqufs_mlist_append(cqufs, (struct cqufs_mlist *)file);

#ifdef CQUFS_READONLY
    if (tag == CQUFS_ERR_NOENT) {
        err = CQUFS_ERR_NOENT;
        goto cleanup;
#else
    if (tag == CQUFS_ERR_NOENT) {
        if (!(flags & CQUFS_O_CREAT)) {
            err = CQUFS_ERR_NOENT;
            goto cleanup;
        }

        cqufs_size_t nlen = strlen(path);                     /*  ��������Ƿ�ƥ��   */
        if (nlen > cqufs->name_max) {
            err = CQUFS_ERR_NAMETOOLONG;
            goto cleanup;
        }

        err = cqufs_dir_commit(cqufs, &file->m, CQUFS_MKATTRS(                     /*  ��ȡ��һ���۲�������Ŀ����סname   */
                {CQUFS_MKTAG(CQUFS_TYPE_CREATE, file->id, 0), NULL},
                {CQUFS_MKTAG(CQUFS_TYPE_REG, file->id, nlen), path},
                {CQUFS_MKTAG(CQUFS_TYPE_INLINESTRUCT, file->id, 0), NULL}));

        err = (err == CQUFS_ERR_NOSPC) ? CQUFS_ERR_NAMETOOLONG : err;
        if (err) {
            goto cleanup;
        }

        tag = CQUFS_MKTAG(CQUFS_TYPE_INLINESTRUCT, 0, 0);
    } else if (flags & CQUFS_O_EXCL) {
        err = CQUFS_ERR_EXIST;
        goto cleanup;
#endif
    } else if (cqufs_tag_type3(tag) != CQUFS_TYPE_REG) {
        err = CQUFS_ERR_ISDIR;
        goto cleanup;
#ifndef CQUFS_READONLY
    } else if (flags & CQUFS_O_TRUNC) {                             /*  �������ض�   */
        tag = CQUFS_MKTAG(CQUFS_TYPE_INLINESTRUCT, file->id, 0);
        file->flags |= CQUFS_F_DIRTY;
#endif
    } else {
        tag = cqufs_dir_get(cqufs, &file->m, CQUFS_MKTAG(0x700, 0x3ff, 0),                     /*  ���Լ��ش����ϵ����ݣ�������������ģ����Ժ��޸���   */
                CQUFS_MKTAG(CQUFS_TYPE_STRUCT, file->id, 8), &file->ctz);
        if (tag < 0) {
            err = tag;
            goto cleanup;
        }
        cqufs_ctz_fromle32(&file->ctz);
    }

    /*  ˵������ȡattrs  */
    unsigned i;
    for (i = 0; i < file->cfg->attr_count; i++) {
        if ((file->flags & CQUFS_O_RDONLY) == CQUFS_O_RDONLY) {                     /*   ���Ϊ��д������  */
            cqufs_stag_t res = cqufs_dir_get(cqufs, &file->m,
                    CQUFS_MKTAG(0x7ff, 0x3ff, 0),
                    CQUFS_MKTAG(CQUFS_TYPE_USERATTR + file->cfg->attrs[i].type,
                        file->id, file->cfg->attrs[i].size),
                        file->cfg->attrs[i].buffer);
            if (res < 0 && res != CQUFS_ERR_NOENT) {
                err = res;
                goto cleanup;
            }
        }

#ifndef CQUFS_READONLY
        if ((file->flags & CQUFS_O_WRONLY) == CQUFS_O_WRONLY) {                     /*  ���Ϊд/��д������   */
            if (file->cfg->attrs[i].size > cqufs->attr_max) {
                err = CQUFS_ERR_NOSPC;
                goto cleanup;
            }

            file->flags |= CQUFS_F_DIRTY;
        }
#endif
    }

    if (file->cfg->buffer) {                     /*  �����Ҫ�����仺����   */
        file->cache.buffer = file->cfg->buffer;
    } else {
        file->cache.buffer = cqufs_malloc(cqufs->cfg->cache_size);
        if (!file->cache.buffer) {
            err = CQUFS_ERR_NOMEM;
            goto cleanup;
        }
    }

    cqufs_cache_zero(cqufs, &file->cache);                     /*   ���㣬�Ա�����Ϣй¶  */

    if (cqufs_tag_type3(tag) == CQUFS_TYPE_INLINESTRUCT) {
        file->ctz.head = CQUFS_BLOCK_INLINE;                     /*  ���������ļ�   */
        file->ctz.size = cqufs_tag_size(tag);
        file->flags |= CQUFS_F_INLINE;
        file->cache.block = file->ctz.head;
        file->cache.off = 0;
        file->cache.size = cqufs->cfg->cache_size;

        if (file->ctz.size > 0) {                     /* �����Ƕ�ȡ    */
            cqufs_stag_t res = cqufs_dir_get(cqufs, &file->m,
                    CQUFS_MKTAG(0x700, 0x3ff, 0),
                    CQUFS_MKTAG(CQUFS_TYPE_STRUCT, file->id,
                        cqufs_min(file->cache.size, 0x3fe)),
                    file->cache.buffer);
            if (res < 0) {
                err = res;
                goto cleanup;
            }
        }
    }

    return 0;

cleanup:                                        /* ���������Դ    */
#ifndef CQUFS_READONLY
    file->flags |= CQUFS_F_ERRED;
#endif
    cqufs_file_rawclose(cqufs, file);
    return err;
}

static int cqufs_file_rawopen(cqufs_t *cqufs, cqufs_file_t *file,
        const char *path, int flags) {
    static const struct cqufs_file_config defaults = {0};
    int err = cqufs_file_rawopencfg(cqufs, file, path, flags, &defaults);
    return err;
}

static int cqufs_file_rawclose(cqufs_t *cqufs, cqufs_file_t *file) {
#ifndef CQUFS_READONLY
    int err = cqufs_file_rawsync(cqufs, file);
#else
    int err = 0;
#endif

    cqufs_mlist_remove(cqufs, (struct cqufs_mlist*)file);                     /*  ��Ԫ�����б���ɾ��   */

    if (!file->cfg->buffer) {                     /*   �����ڴ�  */
        cqufs_free(file->cache.buffer);
    }

    return err;
}


#ifndef CQUFS_READONLY
static int cqufs_file_relocate(cqufs_t *cqufs, cqufs_file_t *file) {
    while (true) {
        cqufs_block_t nblock;                     /*  ���¶�λ���µĿ�   */
        int err = cqufs_alloc(cqufs, &nblock);
        if (err) {
            return err;
        }

        err = cqufs_bd_erase(cqufs, nblock);
        if (err) {
            if (err == CQUFS_ERR_CORRUPT) {
                goto relocate;
            }
            return err;
        }

        cqufs_off_t i;                     /*  ���໺�����̶�ȡ   */
        for (i = 0; i < file->off; i++) {
            uint8_t data;
            if (file->flags & CQUFS_F_INLINE) {
                err = cqufs_dir_getread(cqufs, &file->m,
                        NULL, &file->cache, file->off-i,                     /*  �������ļ�������ļ�֮ǰ�������   */
                        CQUFS_MKTAG(0xfff, 0x1ff, 0),
                        CQUFS_MKTAG(CQUFS_TYPE_INLINESTRUCT, file->id, 0),
                        i, &data, 1);
                if (err) {
                    return err;
                }
            } else {
                err = cqufs_bd_read(cqufs,
                        &file->cache, &cqufs->rcache, file->off-i,
                        file->block, i, &data, 1);
                if (err) {
                    return err;
                }
            }

            err = cqufs_bd_prog(cqufs,
                    &cqufs->pcache, &cqufs->rcache, true,
                    nblock, i, &data, 1);
            if (err) {
                if (err == CQUFS_ERR_CORRUPT) {
                    goto relocate;
                }
                return err;
            }
        }

        memcpy(file->cache.buffer, cqufs->pcache.buffer, cqufs->cfg->cache_size);                     /*  /�����ļ�����״̬   */
        file->cache.block = cqufs->pcache.block;
        file->cache.off = cqufs->pcache.off;
        file->cache.size = cqufs->pcache.size;
        cqufs_cache_zero(cqufs, &cqufs->pcache);

        file->block = nblock;
        file->flags |= CQUFS_F_WRITING;
        return 0;

relocate:
        CQUFS_DEBUG("Bad block at 0x%"PRIx32, nblock);

        cqufs_cache_drop(cqufs, &cqufs->pcache);                     /*  �����沢�����µĿ�   */
    }
}
#endif

#ifndef CQUFS_READONLY
static int cqufs_file_outline(cqufs_t *cqufs, cqufs_file_t *file) {
    file->off = file->pos;
    cqufs_alloc_ack(cqufs);
    int err = cqufs_file_relocate(cqufs, file);
    if (err) {
        return err;
    }

    file->flags &= ~CQUFS_F_INLINE;
    return 0;
}
#endif

static int cqufs_file_flush(cqufs_t *cqufs, cqufs_file_t *file) {
    if (file->flags & CQUFS_F_READING) {
        if (!(file->flags & CQUFS_F_INLINE)) {
            cqufs_cache_drop(cqufs, &file->cache);
        }
        file->flags &= ~CQUFS_F_READING;
    }

#ifndef CQUFS_READONLY
    if (file->flags & CQUFS_F_WRITING) {
        cqufs_off_t pos = file->pos;
        if (!(file->flags & CQUFS_F_INLINE)) {
            cqufs_file_t orig = {                     /*  ���Ƶ�ǰ��֧֮����κ�����   */
                .ctz.head = file->ctz.head,
                .ctz.size = file->ctz.size,
                .flags = CQUFS_O_RDONLY,
                .pos = file->pos,
                .cache = cqufs->rcache,
            };
            cqufs_cache_drop(cqufs, &cqufs->rcache);

            while (file->pos < file->ctz.size) {
                uint8_t data;                     /* ÿ�θ���һ���ֽ�    */
                cqufs_ssize_t res = cqufs_file_flushedread(cqufs, &orig, &data, 1);
                if (res < 0) {
                    return res;
                }

                res = cqufs_file_flushedwrite(cqufs, file, &data, 1);
                if (res < 0) {
                    return res;
                }

                if (cqufs->rcache.block != CQUFS_BLOCK_NULL) {
                    cqufs_cache_drop(cqufs, &orig.cache);
                    cqufs_cache_drop(cqufs, &cqufs->rcache);
                }
            }

            while (true) {
                int err = cqufs_bd_flush(cqufs, &file->cache, &cqufs->rcache, true);
                if (err) {
                    if (err == CQUFS_ERR_CORRUPT) {
                        goto relocate;
                    }
                    return err;
                }

                break;

relocate:
                CQUFS_DEBUG("Bad block at 0x%"PRIx32, file->block);
                err = cqufs_file_relocate(cqufs, file);
                if (err) {
                    return err;
                }
            }
        } else {
            file->pos = cqufs_max(file->pos, file->ctz.size);
        }

        file->ctz.head = file->block;                     /*  ʵ���ļ�����   */
        file->ctz.size = file->pos;
        file->flags &= ~CQUFS_F_WRITING;
        file->flags |= CQUFS_F_DIRTY;

        file->pos = pos;
    }
#endif

    return 0;
}

#ifndef CQUFS_READONLY
static int cqufs_file_rawsync(cqufs_t *cqufs, cqufs_file_t *file) {
    if (file->flags & CQUFS_F_ERRED) {
        return 0;
    }

    int err = cqufs_file_flush(cqufs, file);
    if (err) {
        file->flags |= CQUFS_F_ERRED;
        return err;
    }


    if ((file->flags & CQUFS_F_DIRTY) &&
            !cqufs_pair_isnull(file->m.pair)) {
        uint16_t type;                     /*  /����Ŀ¼��Ŀ   */
        const void *buffer;
        cqufs_size_t size;
        struct cqufs_ctz ctz;
        if (file->flags & CQUFS_F_INLINE) {
            type = CQUFS_TYPE_INLINESTRUCT;                     /*   ���������ļ�  */
            buffer = file->cache.buffer;
            size = file->ctz.size;
        } else {
            type = CQUFS_TYPE_CTZSTRUCT;                     /*  ����CTZ����   */
            ctz = file->ctz;                     /*  ����CTZ��ʹalloc�����¶�λ�ڼ乤��   */
            cqufs_ctz_tole32(&ctz);
            buffer = &ctz;
            size = sizeof(ctz);
        }


        err = cqufs_dir_commit(cqufs, &file->m, CQUFS_MKATTRS(                     /*  �ύ�ļ����ݺ�����   */
                {CQUFS_MKTAG(type, file->id, size), buffer},
                {CQUFS_MKTAG(CQUFS_FROM_USERATTRS, file->id,
                    file->cfg->attr_count), file->cfg->attrs}));
        if (err) {
            file->flags |= CQUFS_F_ERRED;
            return err;
        }

        file->flags &= ~CQUFS_F_DIRTY;
    }

    return 0;
}
#endif

static cqufs_ssize_t cqufs_file_flushedread(cqufs_t *cqufs, cqufs_file_t *file,
        void *buffer, cqufs_size_t size) {
    uint8_t *data = buffer;
    cqufs_size_t nsize = size;

    if (file->pos >= file->ctz.size) {
        return 0;
    }

    size = cqufs_min(size, file->ctz.size - file->pos);
    nsize = size;

    while (nsize > 0) {
        if (!(file->flags & CQUFS_F_READING) ||
                file->off == cqufs->cfg->block_size) {                     /*  ����Ƿ���Ҫһ���µĿ�   */
            if (!(file->flags & CQUFS_F_INLINE)) {
                int err = cqufs_ctz_find(cqufs, NULL, &file->cache,
                        file->ctz.head, file->ctz.size,
                        file->pos, &file->block, &file->off);
                if (err) {
                    return err;
                }
            } else {
                file->block = CQUFS_BLOCK_INLINE;
                file->off = file->pos;
            }

            file->flags |= CQUFS_F_READING;
        }

        cqufs_size_t diff = cqufs_min(nsize, cqufs->cfg->block_size - file->off);                     /*   �ڵ�ǰ���ж�ȡ�����ܶ������  */
        if (file->flags & CQUFS_F_INLINE) {
            int err = cqufs_dir_getread(cqufs, &file->m,
                    NULL, &file->cache, cqufs->cfg->block_size,
                    CQUFS_MKTAG(0xfff, 0x1ff, 0),
                    CQUFS_MKTAG(CQUFS_TYPE_INLINESTRUCT, file->id, 0),
                    file->off, data, diff);
            if (err) {
                return err;
            }
        } else {
            int err = cqufs_bd_read(cqufs,
                    NULL, &file->cache, cqufs->cfg->block_size,
                    file->block, file->off, data, diff);
            if (err) {
                return err;
            }
        }

        file->pos += diff;
        file->off += diff;
        data += diff;
        nsize -= diff;
    }

    return size;
}

static cqufs_ssize_t cqufs_file_rawread(cqufs_t *cqufs, cqufs_file_t *file,
        void *buffer, cqufs_size_t size) {
    CQUFS_ASSERT((file->flags & CQUFS_O_RDONLY) == CQUFS_O_RDONLY);

#ifndef CQUFS_READONLY
    if (file->flags & CQUFS_F_WRITING) {

        int err = cqufs_file_flush(cqufs, file);                     /*  �������д�����   */
        if (err) {
            return err;
        }
    }
#endif

    return cqufs_file_flushedread(cqufs, file, buffer, size);
}


#ifndef CQUFS_READONLY
static cqufs_ssize_t cqufs_file_flushedwrite(cqufs_t *cqufs, cqufs_file_t *file,
        const void *buffer, cqufs_size_t size) {
    const uint8_t *data = buffer;
    cqufs_size_t nsize = size;

    if ((file->flags & CQUFS_F_INLINE) &&
            cqufs_max(file->pos+nsize, file->ctz.size) >
            cqufs_min(0x3fe, cqufs_min(
                cqufs->cfg->cache_size,
                (cqufs->cfg->metadata_max ?
                    cqufs->cfg->metadata_max : cqufs->cfg->block_size) / 8))) {
        int err = cqufs_file_outline(cqufs, file);                     /*  �����ļ������ʺ�   */
        if (err) {
            file->flags |= CQUFS_F_ERRED;
            return err;
        }
    }

    while (nsize > 0) {
        if (!(file->flags & CQUFS_F_WRITING) ||
                file->off == cqufs->cfg->block_size) {                     /*  ��������Ƿ���Ҫһ���µĿ�   */
            if (!(file->flags & CQUFS_F_INLINE)) {
                if (!(file->flags & CQUFS_F_WRITING) && file->pos > 0) {
                    int err = cqufs_ctz_find(cqufs, NULL, &file->cache,                     /*  �ҳ����Ǵ��ĸ�����չ   */
                            file->ctz.head, file->ctz.size,
                            file->pos-1, &file->block, &file->off);
                    if (err) {
                        file->flags |= CQUFS_F_ERRED;
                        return err;
                    }

                    cqufs_cache_zero(cqufs, &file->cache);                     /*  ��cache���Ϊdirty����Ϊ���ǿ����Ѿ���cache�ж�ȡ������   */
                }

                cqufs_alloc_ack(cqufs);                     /*  ��չ�ļ����µĿ�   */
                int err = cqufs_ctz_extend(cqufs, &file->cache, &cqufs->rcache,
                        file->block, file->pos,
                        &file->block, &file->off);
                if (err) {
                    file->flags |= CQUFS_F_ERRED;
                    return err;
                }
            } else {
                file->block = CQUFS_BLOCK_INLINE;
                file->off = file->pos;
            }

            file->flags |= CQUFS_F_WRITING;
        }

        cqufs_size_t diff = cqufs_min(nsize, cqufs->cfg->block_size - file->off);                     /*  �ڵ�ǰ���о����ܶ��д��   */
        while (true) {
            int err = cqufs_bd_prog(cqufs, &file->cache, &cqufs->rcache, true,
                    file->block, file->off, data, diff);
            if (err) {
                if (err == CQUFS_ERR_CORRUPT) {
                    goto relocate;
                }
                file->flags |= CQUFS_F_ERRED;
                return err;
            }

            break;
relocate:
            err = cqufs_file_relocate(cqufs, file);
            if (err) {
                file->flags |= CQUFS_F_ERRED;
                return err;
            }
        }

        file->pos += diff;
        file->off += diff;
        data += diff;
        nsize -= diff;

        cqufs_alloc_ack(cqufs);
    }

    return size;
}

static cqufs_ssize_t cqufs_file_rawwrite(cqufs_t *cqufs, cqufs_file_t *file,
        const void *buffer, cqufs_size_t size) {
    CQUFS_ASSERT((file->flags & CQUFS_O_WRONLY) == CQUFS_O_WRONLY);

    if (file->flags & CQUFS_F_READING) {
        int err = cqufs_file_flush(cqufs, file);                     /*  ɾ���κζ�ȡ   */
        if (err) {
            return err;
        }
    }

    if ((file->flags & CQUFS_O_APPEND) && file->pos < file->ctz.size) {
        file->pos = file->ctz.size;
    }

    if (file->pos + size > cqufs->file_max) {                     /*  �ļ���С��������   */
        return CQUFS_ERR_FBIG;
    }

    if (!(file->flags & CQUFS_F_WRITING) && file->pos > file->ctz.size) {
        cqufs_off_t pos = file->pos;                     /* ���0    */
        file->pos = file->ctz.size;

        while (file->pos < pos) {
            cqufs_ssize_t res = cqufs_file_flushedwrite(cqufs, file, &(uint8_t){0}, 1);
            if (res < 0) {
                return res;
            }
        }
    }

    cqufs_ssize_t nsize = cqufs_file_flushedwrite(cqufs, file, buffer, size);
    if (nsize < 0) {
        return nsize;
    }

    file->flags &= ~CQUFS_F_ERRED;
    return nsize;
}
#endif

static cqufs_soff_t cqufs_file_rawseek(cqufs_t *cqufs, cqufs_file_t *file,
        cqufs_soff_t off, int whence) {
    cqufs_off_t npos = file->pos;                     /*  Ѱ���µ�pos   */
    if (whence == CQUFS_SEEK_SET) {
        npos = off;
    } else if (whence == CQUFS_SEEK_CUR) {
        if ((cqufs_soff_t)file->pos + off < 0) {
            return CQUFS_ERR_INVAL;
        } else {
            npos = file->pos + off;
        }
    } else if (whence == CQUFS_SEEK_END) {
        cqufs_soff_t res = cqufs_file_rawsize(cqufs, file) + off;
        if (res < 0) {
            return CQUFS_ERR_INVAL;
        } else {
            npos = res;
        }
    }

    if (npos > cqufs->file_max) {                     /*  �ļ�λ�ó�����Χ   */
        return CQUFS_ERR_INVAL;
    }

    if (file->pos == npos) {
        return npos;
    }

    if (
#ifndef CQUFS_READONLY
        !(file->flags & CQUFS_F_WRITING)
#else
        true
#endif
            ) {
        int oindex = cqufs_ctz_index(cqufs, &(cqufs_off_t){file->pos});
        cqufs_off_t noff = npos;
        int nindex = cqufs_ctz_index(cqufs, &noff);
        if (oindex == nindex
                && noff >= file->cache.off
                && noff < file->cache.off + file->cache.size) {
            file->pos = npos;
            file->off = noff;
            return npos;
        }
    }


    int err = cqufs_file_flush(cqufs, file);                     /*   Ԥ��д����������  */
    if (err) {
        return err;
    }

    file->pos = npos;                     /*  ����pos   */
    return npos;
}

#ifndef CQUFS_READONLY
static int cqufs_file_rawtruncate(cqufs_t *cqufs, cqufs_file_t *file, cqufs_off_t size) {
    CQUFS_ASSERT((file->flags & CQUFS_O_WRONLY) == CQUFS_O_WRONLY);

    if (size > CQUFS_FILE_MAX) {
        return CQUFS_ERR_INVAL;
    }

    cqufs_off_t pos = file->pos;
    cqufs_off_t oldsize = cqufs_file_rawsize(cqufs, file);
    if (size < oldsize) {
        int err = cqufs_file_flush(cqufs, file);                     /*  ��Ҫˢ�£���Ϊֱ�Ӹ�����Ԫ����   */
        if (err) {
            return err;
        }

        err = cqufs_ctz_find(cqufs, NULL, &file->cache,                     /*  ��CTZ��Ծ���в����µ�ͷ   */
                file->ctz.head, file->ctz.size,
                size, &file->block, &file->off);
        if (err) {
            return err;
        }

        file->pos = size;
        file->ctz.head = file->block;
        file->ctz.size = size;
        file->flags |= CQUFS_F_DIRTY | CQUFS_F_READING;
    } else if (size > oldsize) {
        cqufs_soff_t res = cqufs_file_rawseek(cqufs, file, 0, CQUFS_SEEK_END);                     /*  flush+seek�����û�н���   */
        if (res < 0) {
            return (int)res;
        }


        while (file->pos < size) {                     /*   ���0  */
            res = cqufs_file_rawwrite(cqufs, file, &(uint8_t){0}, 1);
            if (res < 0) {
                return (int)res;
            }
        }
    }

    cqufs_soff_t res = cqufs_file_rawseek(cqufs, file, pos, CQUFS_SEEK_SET);                     /*  �ָ�pos   */
    if (res < 0) {
      return (int)res;
    }

    return 0;
}
#endif

static cqufs_soff_t cqufs_file_rawtell(cqufs_t *cqufs, cqufs_file_t *file) {
    (void)cqufs;
    return file->pos;
}

static int cqufs_file_rawrewind(cqufs_t *cqufs, cqufs_file_t *file) {
    cqufs_soff_t res = cqufs_file_rawseek(cqufs, file, 0, CQUFS_SEEK_SET);
    if (res < 0) {
        return (int)res;
    }

    return 0;
}

static cqufs_soff_t cqufs_file_rawsize(cqufs_t *cqufs, cqufs_file_t *file) {
    (void)cqufs;

#ifndef CQUFS_READONLY
    if (file->flags & CQUFS_F_WRITING) {
        return cqufs_max(file->pos, file->ctz.size);
    }
#endif

    return file->ctz.size;
}

/*********************************************************************************************************
     һ�����
*********************************************************************************************************/
static int cqufs_rawstat(cqufs_t *cqufs, const char *path, struct cqufs_info *info) {
    cqufs_mdir_t cwd;
    cqufs_stag_t tag = cqufs_dir_find(cqufs, &cwd, &path, NULL);
    if (tag < 0) {
        return (int)tag;
    }

    return cqufs_dir_getinfo(cqufs, &cwd, cqufs_tag_id(tag), info);
}

#ifndef CQUFS_READONLY
static int cqufs_rawremove(cqufs_t *cqufs, const char *path) {
    int err = cqufs_fs_forceconsistency(cqufs);
    if (err) {
        return err;
    }

    cqufs_mdir_t cwd;
    cqufs_stag_t tag = cqufs_dir_find(cqufs, &cwd, &path, NULL);
    if (tag < 0 || cqufs_tag_id(tag) == 0x3ff) {
        return (tag < 0) ? (int)tag : CQUFS_ERR_INVAL;
    }

    struct cqufs_mlist dir;
    dir.next = cqufs->mlist;
    if (cqufs_tag_type3(tag) == CQUFS_TYPE_DIR) {
        cqufs_block_t pair[2];                                   /*   ����Ϊ��  */
        cqufs_stag_t res = cqufs_dir_get(cqufs, &cwd, CQUFS_MKTAG(0x700, 0x3ff, 0),
                CQUFS_MKTAG(CQUFS_TYPE_STRUCT, cqufs_tag_id(tag), 8), pair);
        if (res < 0) {
            return (int)res;
        }
        cqufs_pair_fromle32(pair);

        err = cqufs_dir_fetch(cqufs, &dir.m, pair);
        if (err) {
            return err;
        }

        if (dir.m.count > 0 || dir.m.split) {
            return CQUFS_ERR_NOTEMPTY;
        }

        err = cqufs_fs_preporphans(cqufs, +1);                     /*  ���ļ�ϵͳ���Ϊ������   */
        if (err) {
            return err;
        }

        dir.type = 0;
        dir.id = 0;
        cqufs->mlist = &dir;
    }

    err = cqufs_dir_commit(cqufs, &cwd, CQUFS_MKATTRS(                     /*  ɾ������Ŀ   */
            {CQUFS_MKTAG(CQUFS_TYPE_DELETE, cqufs_tag_id(tag), 0), NULL}));
    if (err) {
        cqufs->mlist = dir.next;
        return err;
    }

    cqufs->mlist = dir.next;
    if (cqufs_tag_type3(tag) == CQUFS_TYPE_DIR) {
        err = cqufs_fs_preporphans(cqufs, -1);                     /*  �̶��¶�   */
        if (err) {
            return err;
        }

        err = cqufs_fs_pred(cqufs, dir.m.pair, &cwd);
        if (err) {
            return err;
        }

        err = cqufs_dir_drop(cqufs, &cwd, &dir.m);
        if (err) {
            return err;
        }
    }

    return 0;
}
#endif

#ifndef CQUFS_READONLY
static int cqufs_rawrename(cqufs_t *cqufs, const char *oldpath, const char *newpath) {
    int err = cqufs_fs_forceconsistency(cqufs);                     /*  ��ͨ��������Ҫһ��   */
    if (err) {
        return err;
    }

    cqufs_mdir_t oldcwd;
    cqufs_stag_t oldtag = cqufs_dir_find(cqufs, &oldcwd, &oldpath, NULL);                     /* ���Ҿ���Ŀ    */
    if (oldtag < 0 || cqufs_tag_id(oldtag) == 0x3ff) {
        return (oldtag < 0) ? (int)oldtag : CQUFS_ERR_INVAL;
    }

    cqufs_mdir_t newcwd;
    uint16_t newid;
    cqufs_stag_t prevtag = cqufs_dir_find(cqufs, &newcwd, &newpath, &newid);                     /*  �ҵ��µ���Ŀ   */
    if ((prevtag < 0 || cqufs_tag_id(prevtag) == 0x3ff) &&
            !(prevtag == CQUFS_ERR_NOENT && newid != 0x3ff)) {
        return (prevtag < 0) ? (int)prevtag : CQUFS_ERR_INVAL;
    }

    /*  ˵���� ��������  */
    bool samepair = (cqufs_pair_cmp(oldcwd.pair, newcwd.pair) == 0);
    uint16_t newoldid = cqufs_tag_id(oldtag);

    struct cqufs_mlist prevdir;
    prevdir.next = cqufs->mlist;
    if (prevtag == CQUFS_ERR_NOENT) {
        cqufs_size_t nlen = strlen(newpath);                     /*  ��������Ƿ�ƥ��  */
        if (nlen > cqufs->name_max) {
            return CQUFS_ERR_NAMETOOLONG;
        }

        if (samepair && newid <= newoldid) {
            newoldid += 1;
        }
    } else if (cqufs_tag_type3(prevtag) != cqufs_tag_type3(oldtag)) {
        return CQUFS_ERR_ISDIR;
    } else if (samepair && newid == newoldid) {
        return 0;
    } else if (cqufs_tag_type3(prevtag) == CQUFS_TYPE_DIR) {                     /*  ����Ϊ��   */
        cqufs_block_t prevpair[2];
        cqufs_stag_t res = cqufs_dir_get(cqufs, &newcwd, CQUFS_MKTAG(0x700, 0x3ff, 0),
                CQUFS_MKTAG(CQUFS_TYPE_STRUCT, newid, 8), prevpair);
        if (res < 0) {
            return (int)res;
        }
        cqufs_pair_fromle32(prevpair);


        err = cqufs_dir_fetch(cqufs, &prevdir.m, prevpair);                     /*  ����Ϊ��   */
        if (err) {
            return err;
        }

        if (prevdir.m.count > 0 || prevdir.m.split) {
            return CQUFS_ERR_NOTEMPTY;
        }

        err = cqufs_fs_preporphans(cqufs, +1);                     /*  ���ļ�ϵͳ���Ϊ�����Ľ��뷭��ҳ��   */
        if (err) {
            return err;
        }


        /*  ˵����dir���Ա���ĸ����   */
        prevdir.type = 0;
        prevdir.id = 0;
        cqufs->mlist = &prevdir;
    }

    if (!samepair) {
        cqufs_fs_prepmove(cqufs, newoldid, oldcwd.pair);
    }


    err = cqufs_dir_commit(cqufs, &newcwd, CQUFS_MKATTRS(                     /*  �ƶ���������   */
            {CQUFS_MKTAG_IF(prevtag != CQUFS_ERR_NOENT,
                CQUFS_TYPE_DELETE, newid, 0), NULL},
            {CQUFS_MKTAG(CQUFS_TYPE_CREATE, newid, 0), NULL},
            {CQUFS_MKTAG(cqufs_tag_type3(oldtag), newid, strlen(newpath)), newpath},
            {CQUFS_MKTAG(CQUFS_FROM_MOVE, newid, cqufs_tag_id(oldtag)), &oldcwd},
            {CQUFS_MKTAG_IF(samepair,
                CQUFS_TYPE_DELETE, newoldid, 0), NULL}));
    if (err) {
        cqufs->mlist = prevdir.next;
        return err;
    }

    if (!samepair && cqufs_gstate_hasmove(&cqufs->gstate)) {                     /*   ׼��gstate��ɾ��moveid  */

        cqufs_fs_prepmove(cqufs, 0x3ff, NULL);
        err = cqufs_dir_commit(cqufs, &oldcwd, CQUFS_MKATTRS(
                {CQUFS_MKTAG(CQUFS_TYPE_DELETE, cqufs_tag_id(oldtag), 0), NULL}));
        if (err) {
            cqufs->mlist = prevdir.next;
            return err;
        }
    }

    cqufs->mlist = prevdir.next;
    if (prevtag != CQUFS_ERR_NOENT
            && cqufs_tag_type3(prevtag) == CQUFS_TYPE_DIR) {
        err = cqufs_fs_preporphans(cqufs, -1);                     /*  �̶��¶�   */
        if (err) {
            return err;
        }

        err = cqufs_fs_pred(cqufs, prevdir.m.pair, &newcwd);
        if (err) {
            return err;
        }

        err = cqufs_dir_drop(cqufs, &newcwd, &prevdir.m);
        if (err) {
            return err;
        }
    }

    return 0;
}
#endif

static cqufs_ssize_t cqufs_rawgetattr(cqufs_t *cqufs, const char *path,
        uint8_t type, void *buffer, cqufs_size_t size) {
    cqufs_mdir_t cwd;
    cqufs_stag_t tag = cqufs_dir_find(cqufs, &cwd, &path, NULL);
    if (tag < 0) {
        return tag;
    }

    uint16_t id = cqufs_tag_id(tag);
    if (id == 0x3ff) {
        id = 0;
        int err = cqufs_dir_fetch(cqufs, &cwd, cqufs->root);                     /*  root���������   */
        if (err) {
            return err;
        }
    }

    tag = cqufs_dir_get(cqufs, &cwd, CQUFS_MKTAG(0x7ff, 0x3ff, 0),
            CQUFS_MKTAG(CQUFS_TYPE_USERATTR + type,
                id, cqufs_min(size, cqufs->attr_max)),
            buffer);
    if (tag < 0) {
        if (tag == CQUFS_ERR_NOENT) {
            return CQUFS_ERR_NOATTR;
        }

        return tag;
    }

    return cqufs_tag_size(tag);
}

#ifndef CQUFS_READONLY
static int cqufs_commitattr(cqufs_t *cqufs, const char *path,
        uint8_t type, const void *buffer, cqufs_size_t size) {
    cqufs_mdir_t cwd;
    cqufs_stag_t tag = cqufs_dir_find(cqufs, &cwd, &path, NULL);
    if (tag < 0) {
        return tag;
    }

    uint16_t id = cqufs_tag_id(tag);
    if (id == 0x3ff) {
        id = 0;
        int err = cqufs_dir_fetch(cqufs, &cwd, cqufs->root);                     /*  root���������   */
        if (err) {
            return err;
        }
    }

    return cqufs_dir_commit(cqufs, &cwd, CQUFS_MKATTRS(
            {CQUFS_MKTAG(CQUFS_TYPE_USERATTR + type, id, size), buffer}));
}
#endif

#ifndef CQUFS_READONLY
static int cqufs_rawsetattr(cqufs_t *cqufs, const char *path,
        uint8_t type, const void *buffer, cqufs_size_t size) {
    if (size > cqufs->attr_max) {
        return CQUFS_ERR_NOSPC;
    }

    return cqufs_commitattr(cqufs, path, type, buffer, size);
}
#endif

#ifndef CQUFS_READONLY
static int cqufs_rawremoveattr(cqufs_t *cqufs, const char *path, uint8_t type) {
    return cqufs_commitattr(cqufs, path, type, NULL, 0x3ff);
}
#endif


/*********************************************************************************************************
  �ļ�ϵͳ����
*********************************************************************************************************/
static int cqufs_init(cqufs_t *cqufs, const struct cqufs_config *cfg) {
    cqufs->cfg = cfg;
    int err = 0;

    CQUFS_ASSERT(cqufs->cfg->read_size != 0);                     /*  ��֤cqufs-cfg��С�Ƿ���ȷ��ʼ��   */
    CQUFS_ASSERT(cqufs->cfg->prog_size != 0);
    CQUFS_ASSERT(cqufs->cfg->cache_size != 0);


    CQUFS_ASSERT(cqufs->cfg->cache_size % cqufs->cfg->read_size == 0);                     /*  �����С�ǻ����С�ı���   */
    CQUFS_ASSERT(cqufs->cfg->cache_size % cqufs->cfg->prog_size == 0);
    CQUFS_ASSERT(cqufs->cfg->block_size % cqufs->cfg->cache_size == 0);


    CQUFS_ASSERT(4*cqufs_npw2(0xffffffff / (cqufs->cfg->block_size-2*4))                     /*  �����С�Ƿ��㹻������ӦCTZָ��   */
            <= cqufs->cfg->block_size);

    CQUFS_ASSERT(cqufs->cfg->block_cycles != 0);


    if (cqufs->cfg->read_buffer) {                     /*  ���ö�cache   */
        cqufs->rcache.buffer = cqufs->cfg->read_buffer;
    } else {
        cqufs->rcache.buffer = cqufs_malloc(cqufs->cfg->cache_size);
        if (!cqufs->rcache.buffer) {
            err = CQUFS_ERR_NOMEM;
            goto cleanup;
        }
    }

    if (cqufs->cfg->prog_buffer) {                     /*  ���ó��򻺴�  */
        cqufs->pcache.buffer = cqufs->cfg->prog_buffer;
    } else {
        cqufs->pcache.buffer = cqufs_malloc(cqufs->cfg->cache_size);
        if (!cqufs->pcache.buffer) {
            err = CQUFS_ERR_NOMEM;
            goto cleanup;
        }
    }


    cqufs_cache_zero(cqufs, &cqufs->rcache);                     /*   ����0�Ա�����Ϣй¶  */
    cqufs_cache_zero(cqufs, &cqufs->pcache);

    CQUFS_ASSERT(cqufs->cfg->lookahead_size > 0);
    CQUFS_ASSERT(cqufs->cfg->lookahead_size % 8 == 0 &&
            (uintptr_t)cqufs->cfg->lookahead_buffer % 4 == 0);
    if (cqufs->cfg->lookahead_buffer) {
        cqufs->free.buffer = cqufs->cfg->lookahead_buffer;
    } else {
        cqufs->free.buffer = cqufs_malloc(cqufs->cfg->lookahead_size);
        if (!cqufs->free.buffer) {
            err = CQUFS_ERR_NOMEM;
            goto cleanup;
        }
    }

    CQUFS_ASSERT(cqufs->cfg->name_max <= CQUFS_NAME_MAX);                     /*  ����С�����Ƿ�����   */
    cqufs->name_max = cqufs->cfg->name_max;
    if (!cqufs->name_max) {
        cqufs->name_max = CQUFS_NAME_MAX;
    }

    CQUFS_ASSERT(cqufs->cfg->file_max <= CQUFS_FILE_MAX);
    cqufs->file_max = cqufs->cfg->file_max;
    if (!cqufs->file_max) {
        cqufs->file_max = CQUFS_FILE_MAX;
    }

    CQUFS_ASSERT(cqufs->cfg->attr_max <= CQUFS_ATTR_MAX);
    cqufs->attr_max = cqufs->cfg->attr_max;
    if (!cqufs->attr_max) {
        cqufs->attr_max = CQUFS_ATTR_MAX;
    }

    CQUFS_ASSERT(cqufs->cfg->metadata_max <= cqufs->cfg->block_size);

    cqufs->root[0] = CQUFS_BLOCK_NULL;                     /*   ����Ĭ��״̬  */
    cqufs->root[1] = CQUFS_BLOCK_NULL;
    cqufs->mlist = NULL;
    cqufs->seed = 0;
    cqufs->gdisk = (cqufs_gstate_t){0};
    cqufs->gstate = (cqufs_gstate_t){0};
    cqufs->gdelta = (cqufs_gstate_t){0};
#ifdef CQUFS_MIGRATE
    cqufs->cqufs1 = NULL;
#endif

    return 0;

cleanup:
    cqufs_deinit(cqufs);
    return err;
}

static int cqufs_deinit(cqufs_t *cqufs) {
    if (!cqufs->cfg->read_buffer) {                     /*  �ͷ��ѷ�����ڴ�   */
        cqufs_free(cqufs->rcache.buffer);
    }

    if (!cqufs->cfg->prog_buffer) {
        cqufs_free(cqufs->pcache.buffer);
    }

    if (!cqufs->cfg->lookahead_buffer) {
        cqufs_free(cqufs->free.buffer);
    }

    return 0;
}

#ifndef CQUFS_READONLY
static int cqufs_rawformat(cqufs_t *cqufs, const struct cqufs_config *cfg) {
    int err = 0;
    {
        err = cqufs_init(cqufs, cfg);
        if (err) {
            return err;
        }

        memset(cqufs->free.buffer, 0, cqufs->cfg->lookahead_size);
        cqufs->free.off = 0;
        cqufs->free.size = cqufs_min(8*cqufs->cfg->lookahead_size,
                cqufs->cfg->block_count);
        cqufs->free.i = 0;
        cqufs_alloc_ack(cqufs);

        cqufs_mdir_t root;                     /*   ������Ŀ¼  */
        err = cqufs_dir_alloc(cqufs, &root);
        if (err) {
            goto cleanup;
        }

        cqufs_superblock_t superblock = {                     /*  д��һ��������   */
            .version     = CQUFS_DISK_VERSION,
            .block_size  = cqufs->cfg->block_size,
            .block_count = cqufs->cfg->block_count,
            .name_max    = cqufs->name_max,
            .file_max    = cqufs->file_max,
            .attr_max    = cqufs->attr_max,
        };

        cqufs_superblock_tole32(&superblock);
        err = cqufs_dir_commit(cqufs, &root, CQUFS_MKATTRS(
                {CQUFS_MKTAG(CQUFS_TYPE_CREATE, 0, 0), NULL},
                {CQUFS_MKTAG(CQUFS_TYPE_SUPERBLOCK, 0, 8), "cqufs"},
                {CQUFS_MKTAG(CQUFS_TYPE_INLINESTRUCT, 0, sizeof(superblock)),
                    &superblock}));
        if (err) {
            goto cleanup;
        }

        root.erased = false;
        err = cqufs_dir_commit(cqufs, &root, NULL, 0);                     /*  ǿ��ѹ��   */
        if (err) {
            goto cleanup;
        }

        err = cqufs_dir_fetch(cqufs, &root, (const cqufs_block_t[2]){0, 1});                     /*   �����Լ�飬��ȡ����  */
        if (err) {
            goto cleanup;
        }
    }

cleanup:
    cqufs_deinit(cqufs);
    return err;

}
#endif

static int cqufs_rawmount(cqufs_t *cqufs, const struct cqufs_config *cfg) {
    printf("before cqufs_init--------------------------\n");
    int err = cqufs_init(cqufs, cfg);
    printf("after cqufs_init---------------------------\n");
    if (err) {
        return err;
    }

    cqufs_mdir_t dir = {.tail = {0, 1}};                     /*  ɨ��Ŀ¼��ĳ�������κ�ȫ�ָ���   */
    cqufs_block_t cycle = 0;
    while (!cqufs_pair_isnull(dir.tail)) {
        if (cycle >= cqufs->cfg->block_count/2) {              /*  ���ֻ�·   */
            err = CQUFS_ERR_CORRUPT;
            goto cleanup;
        }
        cycle += 1;

        printf("before cqufs_dir_fetchmatch--------------------------\n");
        cqufs_stag_t tag = cqufs_dir_fetchmatch(cqufs, &dir, dir.tail,                     /*  ��β�б��л�ȡ��һ����   */
                CQUFS_MKTAG(0x7ff, 0x3ff, 0),
                CQUFS_MKTAG(CQUFS_TYPE_SUPERBLOCK, 0, 8),
                NULL,
                cqufs_dir_find_match, &(struct cqufs_dir_find_match){
                    cqufs, "cqufs", 8});
        printf("after cqufs_dir_fetchmatch---------------------------\n");
        if (tag < 0) {
            printf("tag<0---------------------------\n");
            err = tag;
            goto cleanup;
        }


        if (tag && !cqufs_tag_isdelete(tag)) {                     /*  �Ƿ��ǳ�����   */
            // update root
            cqufs->root[0] = dir.pair[0];
            cqufs->root[1] = dir.pair[1];

            cqufs_superblock_t superblock;                     /*   ��ȡ������  */
            tag = cqufs_dir_get(cqufs, &dir, CQUFS_MKTAG(0x7ff, 0x3ff, 0),
                    CQUFS_MKTAG(CQUFS_TYPE_INLINESTRUCT, 0, sizeof(superblock)),
                    &superblock);
            if (tag < 0) {
                err = tag;
                goto cleanup;
            }
            cqufs_superblock_fromle32(&superblock);

            uint16_t major_version = (0xffff & (superblock.version >> 16));                     /*  ���汾   */
            uint16_t minor_version = (0xffff & (superblock.version >>  0));
            if ((major_version != CQUFS_DISK_VERSION_MAJOR ||
                 minor_version > CQUFS_DISK_VERSION_MINOR)) {
                CQUFS_ERROR("Invalid version v%"PRIu16".%"PRIu16,
                        major_version, minor_version);
                err = CQUFS_ERR_INVAL;
                goto cleanup;
            }

            if (superblock.name_max) {                                 /*  ��鳬��������   */
                if (superblock.name_max > cqufs->name_max) {
                    CQUFS_ERROR("Unsupported name_max (%"PRIu32" > %"PRIu32")",
                            superblock.name_max, cqufs->name_max);
                    err = CQUFS_ERR_INVAL;
                    goto cleanup;
                }

                cqufs->name_max = superblock.name_max;
            }

            if (superblock.file_max) {
                if (superblock.file_max > cqufs->file_max) {
                    CQUFS_ERROR("Unsupported file_max (%"PRIu32" > %"PRIu32")",
                            superblock.file_max, cqufs->file_max);
                    err = CQUFS_ERR_INVAL;
                    goto cleanup;
                }

                cqufs->file_max = superblock.file_max;
            }

            if (superblock.attr_max) {
                if (superblock.attr_max > cqufs->attr_max) {
                    CQUFS_ERROR("Unsupported attr_max (%"PRIu32" > %"PRIu32")",
                            superblock.attr_max, cqufs->attr_max);
                    err = CQUFS_ERR_INVAL;
                    goto cleanup;
                }

                cqufs->attr_max = superblock.attr_max;
            }

            if (superblock.block_count != cqufs->cfg->block_count) {
                CQUFS_ERROR("Invalid block count (%"PRIu32" != %"PRIu32")",
                        superblock.block_count, cqufs->cfg->block_count);
                err = CQUFS_ERR_INVAL;
                goto cleanup;
            }

            if (superblock.block_size != cqufs->cfg->block_size) {
                CQUFS_ERROR("Invalid block size (%"PRIu32" != %"PRIu32")",
                        superblock.block_count, cqufs->cfg->block_count);
                err = CQUFS_ERR_INVAL;
                goto cleanup;
            }
        }


        err = cqufs_dir_getgstate(cqufs, &dir, &cqufs->gstate);                     /*  �Ƿ���gstate   */
        if (err) {
            goto cleanup;
        }
    }


    if (cqufs_pair_isnull(cqufs->root)) {                     /*  �Ƿ��ҵ�����   */
        err = CQUFS_ERR_INVAL;
        goto cleanup;
    }


    if (!cqufs_gstate_iszero(&cqufs->gstate)) {                     /*  ��gstate�����ļ�ϵͳ   */
        CQUFS_DEBUG("Found pending gstate 0x%08"PRIx32"%08"PRIx32"%08"PRIx32,
                cqufs->gstate.tag,
                cqufs->gstate.pair[0],
                cqufs->gstate.pair[1]);
    }
    cqufs->gstate.tag += !cqufs_tag_isvalid(cqufs->gstate.tag);
    cqufs->gdisk = cqufs->gstate;


    cqufs->free.off = cqufs->seed % cqufs->cfg->block_count;                     /*  ���λ������������   */
    cqufs_alloc_drop(cqufs);

    return 0;

cleanup:
    cqufs_rawunmount(cqufs);
    return err;
}

static int cqufs_rawunmount(cqufs_t *cqufs) {
    return cqufs_deinit(cqufs);
}

/*********************************************************************************************************
      Filesystem�ļ�ϵͳ����
*********************************************************************************************************/
int cqufs_fs_rawtraverse(cqufs_t *cqufs,
        int (*cb)(void *data, cqufs_block_t block), void *data,
        bool includeorphans) {

    cqufs_mdir_t dir = {.tail = {0, 1}};                     /*  ����Ԫ���ݶ�   */

/*********************************************************************************************************
      ɾ��cqufs1��ؽṹ
*********************************************************************************************************/
//#ifdef CQUFS_MIGRATE
//
//    if (cqufs->cqufs1) {
//        int err = cqufs1_traverse(cqufs, cb, data);
//        if (err) {
//            return err;
//        }
//
//        dir.tail[0] = cqufs->root[0];
//        dir.tail[1] = cqufs->root[1];
//    }
//#endif

    cqufs_block_t cycle = 0;
    while (!cqufs_pair_isnull(dir.tail)) {
        if (cycle >= cqufs->cfg->block_count/2) {                     /*  ���ֻ�·   */
            return CQUFS_ERR_CORRUPT;
        }
        cycle += 1;
        int i;
        for (i = 0; i < 2; i++) {
            int err = cb(data, dir.tail[i]);
            if (err) {
                return err;
            }
        }


        int err = cqufs_dir_fetch(cqufs, &dir, dir.tail);                     /*  ����Ŀ¼�е�id   */
        if (err) {
            return err;
        }
        uint16_t id ;
        for (id = 0; id < dir.count; id++) {
            struct cqufs_ctz ctz;
            cqufs_stag_t tag = cqufs_dir_get(cqufs, &dir, CQUFS_MKTAG(0x700, 0x3ff, 0),
                    CQUFS_MKTAG(CQUFS_TYPE_STRUCT, id, sizeof(ctz)), &ctz);
            if (tag < 0) {
                if (tag == CQUFS_ERR_NOENT) {
                    continue;
                }
                return tag;
            }
            cqufs_ctz_fromle32(&ctz);

            if (cqufs_tag_type3(tag) == CQUFS_TYPE_CTZSTRUCT) {
                err = cqufs_ctz_traverse(cqufs, NULL, &cqufs->rcache,
                        ctz.head, ctz.size, cb, data);
                if (err) {
                    return err;
                }
            } else if (includeorphans &&
                    cqufs_tag_type3(tag) == CQUFS_TYPE_DIRSTRUCT) {
                int i;
                for (i = 0; i < 2; i++) {
                    err = cb(data, (&ctz.head)[i]);
                    if (err) {
                        return err;
                    }
                }
            }
        }
    }

#ifndef CQUFS_READONLY
    cqufs_file_t *f;
    for (f = (cqufs_file_t*)cqufs->mlist; f; f = f->next) {                     /*  �����κδ򿪵��ļ�   */
        if (f->type != CQUFS_TYPE_REG) {
            continue;
        }

        if ((f->flags & CQUFS_F_DIRTY) && !(f->flags & CQUFS_F_INLINE)) {
            int err = cqufs_ctz_traverse(cqufs, &f->cache, &cqufs->rcache,
                    f->ctz.head, f->ctz.size, cb, data);
            if (err) {
                return err;
            }
        }

        if ((f->flags & CQUFS_F_WRITING) && !(f->flags & CQUFS_F_INLINE)) {
            int err = cqufs_ctz_traverse(cqufs, &f->cache, &cqufs->rcache,
                    f->block, f->pos, cb, data);
            if (err) {
                return err;
            }
        }
    }
#endif

    return 0;
}

#ifndef CQUFS_READONLY
static int cqufs_fs_pred(cqufs_t *cqufs,
        const cqufs_block_t pair[2], cqufs_mdir_t *pdir) {                     /*  ��������Ŀ¼��Ŀ¼��Ŀ   */
    pdir->tail[0] = 0;
    pdir->tail[1] = 1;
    cqufs_block_t cycle = 0;
    while (!cqufs_pair_isnull(pdir->tail)) {
        if (cycle >= cqufs->cfg->block_count/2) {                     /*  ���ֻ�·   */
            return CQUFS_ERR_CORRUPT;
        }
        cycle += 1;

        if (cqufs_pair_cmp(pdir->tail, pair) == 0) {
            return 0;
        }

        int err = cqufs_dir_fetch(cqufs, pdir, pdir->tail);
        if (err) {
            return err;
        }
    }

    return CQUFS_ERR_NOENT;
}
#endif

#ifndef CQUFS_READONLY
struct cqufs_fs_parent_match {
    cqufs_t *cqufs;
    const cqufs_block_t pair[2];
};
#endif

#ifndef CQUFS_READONLY
static int cqufs_fs_parent_match(void *data,
        cqufs_tag_t tag, const void *buffer) {
    struct cqufs_fs_parent_match *find = data;
    cqufs_t *cqufs = find->cqufs;
    const struct cqufs_diskoff *disk = buffer;
    (void)tag;

    cqufs_block_t child[2];
    int err = cqufs_bd_read(cqufs,
            &cqufs->pcache, &cqufs->rcache, cqufs->cfg->block_size,
            disk->block, disk->off, &child, sizeof(child));
    if (err) {
        return err;
    }

    cqufs_pair_fromle32(child);
    return (cqufs_pair_cmp(child, find->pair) == 0) ? CQUFS_CMP_EQ : CQUFS_CMP_LT;
}
#endif

#ifndef CQUFS_READONLY
static cqufs_stag_t cqufs_fs_parent(cqufs_t *cqufs, const cqufs_block_t pair[2],
        cqufs_mdir_t *parent) {
    parent->tail[0] = 0;                 /*  ʹ��fetchmatch��callback���������    */
    parent->tail[1] = 1;
    cqufs_block_t cycle = 0;
    while (!cqufs_pair_isnull(parent->tail)) {
        if (cycle >= cqufs->cfg->block_count/2) {                     /*  ���ֻ�·   */

            return CQUFS_ERR_CORRUPT;
        }
        cycle += 1;

        cqufs_stag_t tag = cqufs_dir_fetchmatch(cqufs, parent, parent->tail,
                CQUFS_MKTAG(0x7ff, 0, 0x3ff),
                CQUFS_MKTAG(CQUFS_TYPE_DIRSTRUCT, 0, 8),
                NULL,
                cqufs_fs_parent_match, &(struct cqufs_fs_parent_match){
                    cqufs, {pair[0], pair[1]}});
        if (tag && tag != CQUFS_ERR_NOENT) {
            return tag;
        }
    }

    return CQUFS_ERR_NOENT;
}
#endif

#ifndef CQUFS_READONLY
static int cqufs_fs_preporphans(cqufs_t *cqufs, int8_t orphans) {
    CQUFS_ASSERT(cqufs_tag_size(cqufs->gstate.tag) > 0 || orphans >= 0);
    cqufs->gstate.tag += orphans;
    cqufs->gstate.tag = ((cqufs->gstate.tag & ~CQUFS_MKTAG(0x800, 0, 0)) |
            ((uint32_t)cqufs_gstate_hasorphans(&cqufs->gstate) << 31));

    return 0;
}
#endif

#ifndef CQUFS_READONLY
static void cqufs_fs_prepmove(cqufs_t *cqufs,
        uint16_t id, const cqufs_block_t pair[2]) {
    cqufs->gstate.tag = ((cqufs->gstate.tag & ~CQUFS_MKTAG(0x7ff, 0x3ff, 0)) |
            ((id != 0x3ff) ? CQUFS_MKTAG(CQUFS_TYPE_DELETE, id, 0) : 0));
    cqufs->gstate.pair[0] = (id != 0x3ff) ? pair[0] : 0;
    cqufs->gstate.pair[1] = (id != 0x3ff) ? pair[1] : 0;
}
#endif

#ifndef CQUFS_READONLY
static int cqufs_fs_demove(cqufs_t *cqufs) {
    if (!cqufs_gstate_hasmove(&cqufs->gdisk)) {
        return 0;
    }


    CQUFS_DEBUG("Fixing move {0x%"PRIx32", 0x%"PRIx32"} 0x%"PRIx16,                     /*   ��������Ĳ���  */
            cqufs->gdisk.pair[0],
            cqufs->gdisk.pair[1],
            cqufs_tag_id(cqufs->gdisk.tag));


    cqufs_mdir_t movedir;
    int err = cqufs_dir_fetch(cqufs, &movedir, cqufs->gdisk.pair);                     /*  ��ȡ��ɾ�����ƶ�����Ŀ   */
    if (err) {
        return err;
    }


    uint16_t moveid = cqufs_tag_id(cqufs->gdisk.tag);                     /*  ׼��gstate��ɾ��moveid   */
    cqufs_fs_prepmove(cqufs, 0x3ff, NULL);
    err = cqufs_dir_commit(cqufs, &movedir, CQUFS_MKATTRS(
            {CQUFS_MKTAG(CQUFS_TYPE_DELETE, moveid, 0), NULL}));
    if (err) {
        return err;
    }

    return 0;
}
#endif

#ifndef CQUFS_READONLY
static int cqufs_fs_deorphan(cqufs_t *cqufs, bool powerloss) {
    if (!cqufs_gstate_hasorphans(&cqufs->gstate)) {
        return 0;
    }

    int8_t found = 0;
restart:
    {

        cqufs_mdir_t pdir = {.split = true, .tail = {0, 1}};                     /*  �޸��¶�   */
        cqufs_mdir_t dir;


        while (!cqufs_pair_isnull(pdir.tail)) {                     /* ��������Ŀ¼��Ŀ¼��Ŀ  */
            int err = cqufs_dir_fetch(cqufs, &dir, pdir.tail);
            if (err) {
                return err;
            }


            if (!pdir.split) {                     /*  ���¶�ͷ����   */

                cqufs_mdir_t parent;
                cqufs_stag_t tag = cqufs_fs_parent(cqufs, pdir.tail, &parent);                     /*  ����Ƿ��и�ĸ   */
                if (tag < 0 && tag != CQUFS_ERR_NOENT) {
                    return tag;
                }

                if (tag == CQUFS_ERR_NOENT && powerloss) {                     /*  �¶�   */

                    CQUFS_DEBUG("Fixing orphan {0x%"PRIx32", 0x%"PRIx32"}",
                            pdir.tail[0], pdir.tail[1]);


                    err = cqufs_dir_getgstate(cqufs, &dir, &cqufs->gdelta);                     /*  ��̬����   */
                    if (err) {
                        return err;
                    }


                    cqufs_pair_tole32(dir.tail);
                    int state = cqufs_dir_orphaningcommit(cqufs, &pdir, CQUFS_MKATTRS(
                            {CQUFS_MKTAG(CQUFS_TYPE_TAIL + dir.split, 0x3ff, 8),
                                dir.tail}));
                    cqufs_pair_fromle32(dir.tail);
                    if (state < 0) {
                        return state;
                    }

                    found += 1;


                    if (state == CQUFS_OK_ORPHANED) {                     /*  �Ƿ����˸���Ĺ¶�   */
                        goto restart;
                    }


                    continue;                     /*  ����ȡ��β��   */
                }

                if (tag != CQUFS_ERR_NOENT) {
                    cqufs_block_t pair[2];
                    cqufs_stag_t state = cqufs_dir_get(cqufs, &parent,
                            CQUFS_MKTAG(0x7ff, 0x3ff, 0), tag, pair);
                    if (state < 0) {
                        return state;
                    }
                    cqufs_pair_fromle32(pair);

                    if (!cqufs_pair_sync(pair, pdir.tail)) {                     /*  �Ѿ�ͬ��   */

                        CQUFS_DEBUG("Fixing half-orphan "
                                "{0x%"PRIx32", 0x%"PRIx32"} "
                                "-> {0x%"PRIx32", 0x%"PRIx32"}",
                                pdir.tail[0], pdir.tail[1], pair[0], pair[1]);


                        uint16_t moveid = 0x3ff;
                        if (cqufs_gstate_hasmovehere(&cqufs->gstate, pdir.pair)) {
                            moveid = cqufs_tag_id(cqufs->gstate.tag);
                            CQUFS_DEBUG("Fixing move while fixing orphans "
                                    "{0x%"PRIx32", 0x%"PRIx32"} 0x%"PRIx16"\n",
                                    pdir.pair[0], pdir.pair[1], moveid);
                            cqufs_fs_prepmove(cqufs, 0x3ff, NULL);
                        }

                        cqufs_pair_tole32(pair);
                        state = cqufs_dir_orphaningcommit(cqufs, &pdir, CQUFS_MKATTRS(
                                {CQUFS_MKTAG_IF(moveid != 0x3ff,
                                    CQUFS_TYPE_DELETE, moveid, 0), NULL},
                                {CQUFS_MKTAG(CQUFS_TYPE_SOFTTAIL, 0x3ff, 8),
                                    pair}));
                        cqufs_pair_fromle32(pair);
                        if (state < 0) {
                            return state;
                        }

                        found += 1;


                        if (state == CQUFS_OK_ORPHANED) {                     /*   �Ƿ����˸���Ĺ¶�  */
                            goto restart;
                        }

                                           /* ����ȡ��β��    */
                        continue;
                    }
                }
            }

            pdir = dir;
        }
    }


    return cqufs_fs_preporphans(cqufs, -cqufs_min(                     /*  ���¶����Ϊ�̶���   */
            cqufs_gstate_getorphans(&cqufs->gstate),
            found));
}
#endif

#ifndef CQUFS_READONLY
static int cqufs_fs_forceconsistency(cqufs_t *cqufs) {
    int err = cqufs_fs_demove(cqufs);
    if (err) {
        return err;
    }

    err = cqufs_fs_deorphan(cqufs, true);
    if (err) {
        return err;
    }

    return 0;
}
#endif

static int cqufs_fs_size_count(void *p, cqufs_block_t block) {
    (void)block;
    cqufs_size_t *size = p;
    *size += 1;
    return 0;
}

static cqufs_ssize_t cqufs_fs_rawsize(cqufs_t *cqufs) {
    cqufs_size_t size = 0;
    int err = cqufs_fs_rawtraverse(cqufs, cqufs_fs_size_count, &size, false);
    if (err) {
        return err;
    }

    return size;
}

/*********************************************************************************************************
  cqufs1����غ���ȫ������
*********************************************************************************************************/
//#ifdef CQUFS_MIGRATE
//////// Migration from littecqufs v1 below this //////
//
///// Version info ///
//
//// Software library version
//// Major (top-nibble), incremented on backwards incompatible changes
//// Minor (bottom-nibble), incremented on feature additions
//#define CQUFS1_VERSION 0x00010007
//#define CQUFS1_VERSION_MAJOR (0xffff & (CQUFS1_VERSION >> 16))
//#define CQUFS1_VERSION_MINOR (0xffff & (CQUFS1_VERSION >>  0))
//
//// Version of On-disk data structures
//// Major (top-nibble), incremented on backwards incompatible changes
//// Minor (bottom-nibble), incremented on feature additions
//#define CQUFS1_DISK_VERSION 0x00010001
//#define CQUFS1_DISK_VERSION_MAJOR (0xffff & (CQUFS1_DISK_VERSION >> 16))
//#define CQUFS1_DISK_VERSION_MINOR (0xffff & (CQUFS1_DISK_VERSION >>  0))
//
//
///// v1 Definitions ///
//
//// File types
//enum cqufs1_type {
//    CQUFS1_TYPE_REG        = 0x11,
//    CQUFS1_TYPE_DIR        = 0x22,
//    CQUFS1_TYPE_SUPERBLOCK = 0x2e,
//};
//
//typedef struct cqufs1 {
//    cqufs_block_t root[2];
//} cqufs1_t;
//
//typedef struct cqufs1_entry {
//    cqufs_off_t off;
//
//    struct cqufs1_disk_entry {
//        uint8_t type;
//        uint8_t elen;
//        uint8_t alen;
//        uint8_t nlen;
//        union {
//            struct {
//                cqufs_block_t head;
//                cqufs_size_t size;
//            } file;
//            cqufs_block_t dir[2];
//        } u;
//    } d;
//} cqufs1_entry_t;
//
//typedef struct cqufs1_dir {
//    struct cqufs1_dir *next;
//    cqufs_block_t pair[2];
//    cqufs_off_t off;
//
//    cqufs_block_t head[2];
//    cqufs_off_t pos;
//
//    struct cqufs1_disk_dir {
//        uint32_t rev;
//        cqufs_size_t size;
//        cqufs_block_t tail[2];
//    } d;
//} cqufs1_dir_t;
//
//typedef struct cqufs1_superblock {
//    cqufs_off_t off;
//
//    struct cqufs1_disk_superblock {
//        uint8_t type;
//        uint8_t elen;
//        uint8_t alen;
//        uint8_t nlen;
//        cqufs_block_t root[2];
//        uint32_t block_size;
//        uint32_t block_count;
//        uint32_t version;
//        char magic[8];
//    } d;
//} cqufs1_superblock_t;
//
//
///// Low-level wrappers v1->v2 ///
//static void cqufs1_crc(uint32_t *crc, const void *buffer, size_t size) {
//    *crc = cqufs_crc(*crc, buffer, size);
//}
//
//static int cqufs1_bd_read(cqufs_t *cqufs, cqufs_block_t block,
//        cqufs_off_t off, void *buffer, cqufs_size_t size) {
//    // if we ever do more than writes to alternating pairs,
//    // this may need to consider pcache
//    return cqufs_bd_read(cqufs, &cqufs->pcache, &cqufs->rcache, size,
//            block, off, buffer, size);
//}
//
//static int cqufs1_bd_crc(cqufs_t *cqufs, cqufs_block_t block,
//        cqufs_off_t off, cqufs_size_t size, uint32_t *crc) {
//    for (cqufs_off_t i = 0; i < size; i++) {
//        uint8_t c;
//        int err = cqufs1_bd_read(cqufs, block, off+i, &c, 1);
//        if (err) {
//            return err;
//        }
//
//        cqufs1_crc(crc, &c, 1);
//    }
//
//    return 0;
//}
//
//
///// Endian swapping functions ///
//static void cqufs1_dir_fromle32(struct cqufs1_disk_dir *d) {
//    d->rev     = cqufs_fromle32(d->rev);
//    d->size    = cqufs_fromle32(d->size);
//    d->tail[0] = cqufs_fromle32(d->tail[0]);
//    d->tail[1] = cqufs_fromle32(d->tail[1]);
//}
//
//static void cqufs1_dir_tole32(struct cqufs1_disk_dir *d) {
//    d->rev     = cqufs_tole32(d->rev);
//    d->size    = cqufs_tole32(d->size);
//    d->tail[0] = cqufs_tole32(d->tail[0]);
//    d->tail[1] = cqufs_tole32(d->tail[1]);
//}
//
//static void cqufs1_entry_fromle32(struct cqufs1_disk_entry *d) {
//    d->u.dir[0] = cqufs_fromle32(d->u.dir[0]);
//    d->u.dir[1] = cqufs_fromle32(d->u.dir[1]);
//}
//
//static void cqufs1_entry_tole32(struct cqufs1_disk_entry *d) {
//    d->u.dir[0] = cqufs_tole32(d->u.dir[0]);
//    d->u.dir[1] = cqufs_tole32(d->u.dir[1]);
//}
//
//static void cqufs1_superblock_fromle32(struct cqufs1_disk_superblock *d) {
//    d->root[0]     = cqufs_fromle32(d->root[0]);
//    d->root[1]     = cqufs_fromle32(d->root[1]);
//    d->block_size  = cqufs_fromle32(d->block_size);
//    d->block_count = cqufs_fromle32(d->block_count);
//    d->version     = cqufs_fromle32(d->version);
//}
//
//
/////// Metadata pair and directory operations ///
//static inline cqufs_size_t cqufs1_entry_size(const cqufs1_entry_t *entry) {
//    return 4 + entry->d.elen + entry->d.alen + entry->d.nlen;
//}
//
//static int cqufs1_dir_fetch(cqufs_t *cqufs,
//        cqufs1_dir_t *dir, const cqufs_block_t pair[2]) {
//    // copy out pair, otherwise may be aliasing dir
//    const cqufs_block_t tpair[2] = {pair[0], pair[1]};
//    bool valid = false;
//
//    // check both blocks for the most recent revision
//    for (int i = 0; i < 2; i++) {
//        struct cqufs1_disk_dir test;
//        int err = cqufs1_bd_read(cqufs, tpair[i], 0, &test, sizeof(test));
//        cqufs1_dir_fromle32(&test);
//        if (err) {
//            if (err == CQUFS_ERR_CORRUPT) {
//                continue;
//            }
//            return err;
//        }
//
//        if (valid && cqufs_scmp(test.rev, dir->d.rev) < 0) {
//            continue;
//        }
//
//        if ((0x7fffffff & test.size) < sizeof(test)+4 ||
//            (0x7fffffff & test.size) > cqufs->cfg->block_size) {
//            continue;
//        }
//
//        uint32_t crc = 0xffffffff;
//        cqufs1_dir_tole32(&test);
//        cqufs1_crc(&crc, &test, sizeof(test));
//        cqufs1_dir_fromle32(&test);
//        err = cqufs1_bd_crc(cqufs, tpair[i], sizeof(test),
//                (0x7fffffff & test.size) - sizeof(test), &crc);
//        if (err) {
//            if (err == CQUFS_ERR_CORRUPT) {
//                continue;
//            }
//            return err;
//        }
//
//        if (crc != 0) {
//            continue;
//        }
//
//        valid = true;
//
//        // setup dir in case it's valid
//        dir->pair[0] = tpair[(i+0) % 2];
//        dir->pair[1] = tpair[(i+1) % 2];
//        dir->off = sizeof(dir->d);
//        dir->d = test;
//    }
//
//    if (!valid) {
//        CQUFS_ERROR("Corrupted dir pair at {0x%"PRIx32", 0x%"PRIx32"}",
//                tpair[0], tpair[1]);
//        return CQUFS_ERR_CORRUPT;
//    }
//
//    return 0;
//}
//
//static int cqufs1_dir_next(cqufs_t *cqufs, cqufs1_dir_t *dir, cqufs1_entry_t *entry) {
//    while (dir->off + sizeof(entry->d) > (0x7fffffff & dir->d.size)-4) {
//        if (!(0x80000000 & dir->d.size)) {
//            entry->off = dir->off;
//            return CQUFS_ERR_NOENT;
//        }
//
//        int err = cqufs1_dir_fetch(cqufs, dir, dir->d.tail);
//        if (err) {
//            return err;
//        }
//
//        dir->off = sizeof(dir->d);
//        dir->pos += sizeof(dir->d) + 4;
//    }
//
//    int err = cqufs1_bd_read(cqufs, dir->pair[0], dir->off,
//            &entry->d, sizeof(entry->d));
//    cqufs1_entry_fromle32(&entry->d);
//    if (err) {
//        return err;
//    }
//
//    entry->off = dir->off;
//    dir->off += cqufs1_entry_size(entry);
//    dir->pos += cqufs1_entry_size(entry);
//    return 0;
//}
//
///// littlefs v1 specific operations ///
//int cqufs1_traverse(cqufs_t *cqufs, int (*cb)(void*, cqufs_block_t), void *data) {
//    if (cqufs_pair_isnull(cqufs->cqufs1->root)) {
//        return 0;
//    }
//
//    // iterate over metadata pairs
//    cqufs1_dir_t dir;
//    cqufs1_entry_t entry;
//    cqufs_block_t cwd[2] = {0, 1};
//
//    while (true) {
//        for (int i = 0; i < 2; i++) {
//            int err = cb(data, cwd[i]);
//            if (err) {
//                return err;
//            }
//        }
//
//        int err = cqufs1_dir_fetch(cqufs, &dir, cwd);
//        if (err) {
//            return err;
//        }
//
//        // iterate over contents
//        while (dir.off + sizeof(entry.d) <= (0x7fffffff & dir.d.size)-4) {
//            err = cqufs1_bd_read(cqufs, dir.pair[0], dir.off,
//                    &entry.d, sizeof(entry.d));
//            cqufs1_entry_fromle32(&entry.d);
//            if (err) {
//                return err;
//            }
//
//            dir.off += cqufs1_entry_size(&entry);
//            if ((0x70 & entry.d.type) == (0x70 & CQUFS1_TYPE_REG)) {
//                err = cqufs_ctz_traverse(cqufs, NULL, &cqufs->rcache,
//                        entry.d.u.file.head, entry.d.u.file.size, cb, data);
//                if (err) {
//                    return err;
//                }
//            }
//        }
//
//        // we also need to check if we contain a threaded v2 directory
//        cqufs_mdir_t dir2 = {.split=true, .tail={cwd[0], cwd[1]}};
//        while (dir2.split) {
//            err = cqufs_dir_fetch(cqufs, &dir2, dir2.tail);
//            if (err) {
//                break;
//            }
//
//            for (int i = 0; i < 2; i++) {
//                err = cb(data, dir2.pair[i]);
//                if (err) {
//                    return err;
//                }
//            }
//        }
//
//        cwd[0] = dir.d.tail[0];
//        cwd[1] = dir.d.tail[1];
//
//        if (cqufs_pair_isnull(cwd)) {
//            break;
//        }
//    }
//
//    return 0;
//}
//
//static int cqufs1_moved(cqufs_t *cqufs, const void *e) {
//    if (cqufs_pair_isnull(cqufs->cqufs1->root)) {
//        return 0;
//    }
//
//    // skip superblock
//    cqufs1_dir_t cwd;
//    int err = cqufs1_dir_fetch(cqufs, &cwd, (const cqufs_block_t[2]){0, 1});
//    if (err) {
//        return err;
//    }
//
//    // iterate over all directory directory entries
//    cqufs1_entry_t entry;
//    while (!cqufs_pair_isnull(cwd.d.tail)) {
//        err = cqufs1_dir_fetch(cqufs, &cwd, cwd.d.tail);
//        if (err) {
//            return err;
//        }
//
//        while (true) {
//            err = cqufs1_dir_next(cqufs, &cwd, &entry);
//            if (err && err != CQUFS_ERR_NOENT) {
//                return err;
//            }
//
//            if (err == CQUFS_ERR_NOENT) {
//                break;
//            }
//
//            if (!(0x80 & entry.d.type) &&
//                 memcmp(&entry.d.u, e, sizeof(entry.d.u)) == 0) {
//                return true;
//            }
//        }
//    }
//
//    return false;
//}
//
///// Filesystem operations ///
//static int cqufs1_mount(cqufs_t *cqufs, struct cqufs1 *cqufs1,
//        const struct cqufs_config *cfg) {
//    int err = 0;
//    {
//        err = cqufs_init(cqufs, cfg);
//        if (err) {
//            return err;
//        }
//
//        cqufs->cqufs1 = cqufs1;
//        cqufs->cqufs1->root[0] = CQUFS_BLOCK_NULL;
//        cqufs->cqufs1->root[1] = CQUFS_BLOCK_NULL;
//
//        // setup free lookahead
//        cqufs->free.off = 0;
//        cqufs->free.size = 0;
//        cqufs->free.i = 0;
//        cqufs_alloc_ack(cqufs);
//
//        // load superblock
//        cqufs1_dir_t dir;
//        cqufs1_superblock_t superblock;
//        err = cqufs1_dir_fetch(cqufs, &dir, (const cqufs_block_t[2]){0, 1});
//        if (err && err != CQUFS_ERR_CORRUPT) {
//            goto cleanup;
//        }
//
//        if (!err) {
//            err = cqufs1_bd_read(cqufs, dir.pair[0], sizeof(dir.d),
//                    &superblock.d, sizeof(superblock.d));
//            cqufs1_superblock_fromle32(&superblock.d);
//            if (err) {
//                goto cleanup;
//            }
//
//            cqufs->cqufs1->root[0] = superblock.d.root[0];
//            cqufs->cqufs1->root[1] = superblock.d.root[1];
//        }
//
//        if (err || memcmp(superblock.d.magic, "littlefs", 8) != 0) {
//            CQUFS_ERROR("Invalid superblock at {0x%"PRIx32", 0x%"PRIx32"}",
//                    0, 1);
//            err = CQUFS_ERR_CORRUPT;
//            goto cleanup;
//        }
//
//        uint16_t major_version = (0xffff & (superblock.d.version >> 16));
//        uint16_t minor_version = (0xffff & (superblock.d.version >>  0));
//        if ((major_version != CQUFS1_DISK_VERSION_MAJOR ||
//             minor_version > CQUFS1_DISK_VERSION_MINOR)) {
//            CQUFS_ERROR("Invalid version v%d.%d", major_version, minor_version);
//            err = CQUFS_ERR_INVAL;
//            goto cleanup;
//        }
//
//        return 0;
//    }
//
//cleanup:
//    cqufs_deinit(cqufs);
//    return err;
//}
//
//static int cqufs1_unmount(cqufs_t *cqufs) {
//    return cqufs_deinit(cqufs);
//}
//
///// v1 migration ///
//static int cqufs_rawmigrate(cqufs_t *cqufs, const struct cqufs_config *cfg) {
//    struct cqufs1 cqufs1;
//    int err = cqufs1_mount(cqufs, &cqufs1, cfg);
//    if (err) {
//        return err;
//    }
//
//    {
//        // iterate through each directory, copying over entries
//        // into new directory
//        cqufs1_dir_t dir1;
//        cqufs_mdir_t dir2;
//        dir1.d.tail[0] = cqufs->cqufs1->root[0];
//        dir1.d.tail[1] = cqufs->cqufs1->root[1];
//        while (!cqufs_pair_isnull(dir1.d.tail)) {
//            // iterate old dir
//            err = cqufs1_dir_fetch(cqufs, &dir1, dir1.d.tail);
//            if (err) {
//                goto cleanup;
//            }
//
//            // create new dir and bind as temporary pretend root
//            err = cqufs_dir_alloc(cqufs, &dir2);
//            if (err) {
//                goto cleanup;
//            }
//
//            dir2.rev = dir1.d.rev;
//            dir1.head[0] = dir1.pair[0];
//            dir1.head[1] = dir1.pair[1];
//            cqufs->root[0] = dir2.pair[0];
//            cqufs->root[1] = dir2.pair[1];
//
//            err = cqufs_dir_commit(cqufs, &dir2, NULL, 0);
//            if (err) {
//                goto cleanup;
//            }
//
//            while (true) {
//                cqufs1_entry_t entry1;
//                err = cqufs1_dir_next(cqufs, &dir1, &entry1);
//                if (err && err != CQUFS_ERR_NOENT) {
//                    goto cleanup;
//                }
//
//                if (err == CQUFS_ERR_NOENT) {
//                    break;
//                }
//
//                // check that entry has not been moved
//                if (entry1.d.type & 0x80) {
//                    int moved = cqufs1_moved(cqufs, &entry1.d.u);
//                    if (moved < 0) {
//                        err = moved;
//                        goto cleanup;
//                    }
//
//                    if (moved) {
//                        continue;
//                    }
//
//                    entry1.d.type &= ~0x80;
//                }
//
//                // also fetch name
//                char name[CQUFS_NAME_MAX+1];
//                memset(name, 0, sizeof(name));
//                err = cqufs1_bd_read(cqufs, dir1.pair[0],
//                        entry1.off + 4+entry1.d.elen+entry1.d.alen,
//                        name, entry1.d.nlen);
//                if (err) {
//                    goto cleanup;
//                }
//
//                bool isdir = (entry1.d.type == CQUFS1_TYPE_DIR);
//
//                // create entry in new dir
//                err = cqufs_dir_fetch(cqufs, &dir2, cqufs->root);
//                if (err) {
//                    goto cleanup;
//                }
//
//                uint16_t id;
//                err = cqufs_dir_find(cqufs, &dir2, &(const char*){name}, &id);
//                if (!(err == CQUFS_ERR_NOENT && id != 0x3ff)) {
//                    err = (err < 0) ? err : CQUFS_ERR_EXIST;
//                    goto cleanup;
//                }
//
//                cqufs1_entry_tole32(&entry1.d);
//                err = cqufs_dir_commit(cqufs, &dir2, CQUFS_MKATTRS(
//                        {CQUFS_MKTAG(CQUFS_TYPE_CREATE, id, 0), NULL},
//                        {CQUFS_MKTAG_IF_ELSE(isdir,
//                            CQUFS_TYPE_DIR, id, entry1.d.nlen,
//                            CQUFS_TYPE_REG, id, entry1.d.nlen),
//                                name},
//                        {CQUFS_MKTAG_IF_ELSE(isdir,
//                            CQUFS_TYPE_DIRSTRUCT, id, sizeof(entry1.d.u),
//                            CQUFS_TYPE_CTZSTRUCT, id, sizeof(entry1.d.u)),
//                                &entry1.d.u}));
//                cqufs1_entry_fromle32(&entry1.d);
//                if (err) {
//                    goto cleanup;
//                }
//            }
//
//            if (!cqufs_pair_isnull(dir1.d.tail)) {
//                // find last block and update tail to thread into fs
//                err = cqufs_dir_fetch(cqufs, &dir2, cqufs->root);
//                if (err) {
//                    goto cleanup;
//                }
//
//                while (dir2.split) {
//                    err = cqufs_dir_fetch(cqufs, &dir2, dir2.tail);
//                    if (err) {
//                        goto cleanup;
//                    }
//                }
//
//                cqufs_pair_tole32(dir2.pair);
//                err = cqufs_dir_commit(cqufs, &dir2, CQUFS_MKATTRS(
//                        {CQUFS_MKTAG(CQUFS_TYPE_SOFTTAIL, 0x3ff, 8), dir1.d.tail}));
//                cqufs_pair_fromle32(dir2.pair);
//                if (err) {
//                    goto cleanup;
//                }
//            }
//
//            // Copy over first block to thread into fs. Unfortunately
//            // if this fails there is not much we can do.
//            CQUFS_DEBUG("Migrating {0x%"PRIx32", 0x%"PRIx32"} "
//                        "-> {0x%"PRIx32", 0x%"PRIx32"}",
//                    cqufs->root[0], cqufs->root[1], dir1.head[0], dir1.head[1]);
//
//            err = cqufs_bd_erase(cqufs, dir1.head[1]);
//            if (err) {
//                goto cleanup;
//            }
//
//            err = cqufs_dir_fetch(cqufs, &dir2, cqufs->root);
//            if (err) {
//                goto cleanup;
//            }
//
//            for (cqufs_off_t i = 0; i < dir2.off; i++) {
//                uint8_t dat;
//                err = cqufs_bd_read(cqufs,
//                        NULL, &cqufs->rcache, dir2.off,
//                        dir2.pair[0], i, &dat, 1);
//                if (err) {
//                    goto cleanup;
//                }
//
//                err = cqufs_bd_prog(cqufs,
//                        &cqufs->pcache, &cqufs->rcache, true,
//                        dir1.head[1], i, &dat, 1);
//                if (err) {
//                    goto cleanup;
//                }
//            }
//
//            err = cqufs_bd_flush(cqufs, &cqufs->pcache, &cqufs->rcache, true);
//            if (err) {
//                goto cleanup;
//            }
//        }
//
//        // Create new superblock. This marks a successful migration!
//        err = cqufs1_dir_fetch(cqufs, &dir1, (const cqufs_block_t[2]){0, 1});
//        if (err) {
//            goto cleanup;
//        }
//
//        dir2.pair[0] = dir1.pair[0];
//        dir2.pair[1] = dir1.pair[1];
//        dir2.rev = dir1.d.rev;
//        dir2.off = sizeof(dir2.rev);
//        dir2.etag = 0xffffffff;
//        dir2.count = 0;
//        dir2.tail[0] = cqufs->cqufs1->root[0];
//        dir2.tail[1] = cqufs->cqufs1->root[1];
//        dir2.erased = false;
//        dir2.split = true;
//
//        cqufs_superblock_t superblock = {
//            .version     = CQUFS_DISK_VERSION,
//            .block_size  = cqufs->cfg->block_size,
//            .block_count = cqufs->cfg->block_count,
//            .name_max    = cqufs->name_max,
//            .file_max    = cqufs->file_max,
//            .attr_max    = cqufs->attr_max,
//        };
//
//        cqufs_superblock_tole32(&superblock);
//        err = cqufs_dir_commit(cqufs, &dir2, CQUFS_MKATTRS(
//                {CQUFS_MKTAG(CQUFS_TYPE_CREATE, 0, 0), NULL},
//                {CQUFS_MKTAG(CQUFS_TYPE_SUPERBLOCK, 0, 8), "littlefs"},
//                {CQUFS_MKTAG(CQUFS_TYPE_INLINESTRUCT, 0, sizeof(superblock)),
//                    &superblock}));
//        if (err) {
//            goto cleanup;
//        }
//
//        // sanity check that fetch works
//        err = cqufs_dir_fetch(cqufs, &dir2, (const cqufs_block_t[2]){0, 1});
//        if (err) {
//            goto cleanup;
//        }
//
//        // force compaction to prevent accidentally mounting v1
//        dir2.erased = false;
//        err = cqufs_dir_commit(cqufs, &dir2, NULL, 0);
//        if (err) {
//            goto cleanup;
//        }
//    }
//
//cleanup:
//    cqufs1_unmount(cqufs);
//    return err;
//}
//
//#endif


/*********************************************************************************************************
  ���ź���API /��������̰߳�ȫ�İ�װ��
*********************************************************************************************************/

/*********************************************************************************************************
  �̰߳�ȫ�İ�װ��
*********************************************************************************************************/
#ifdef CQUFS_THREADSAFE
#define CQUFS_LOCK(cfg)   cfg->lock(cfg)
#define CQUFS_UNLOCK(cfg) cfg->unlock(cfg)
#else
#define CQUFS_LOCK(cfg)   ((void)cfg, 0)
#define CQUFS_UNLOCK(cfg) ((void)cfg)
#endif

#ifndef CQUFS_READONLY
int cqufs_format(cqufs_t *cqufs, const struct cqufs_config *cfg) {
    int err = CQUFS_LOCK(cfg);
    if (err) {
        return err;
    }
    CQUFS_TRACE("cqufs_format(%p, %p {.context=%p, "
                ".read=%p, .prog=%p, .erase=%p, .sync=%p, "
                ".read_size=%"PRIu32", .prog_size=%"PRIu32", "
                ".block_size=%"PRIu32", .block_count=%"PRIu32", "
                ".block_cycles=%"PRIu32", .cache_size=%"PRIu32", "
                ".lookahead_size=%"PRIu32", .read_buffer=%p, "
                ".prog_buffer=%p, .lookahead_buffer=%p, "
                ".name_max=%"PRIu32", .file_max=%"PRIu32", "
                ".attr_max=%"PRIu32"})",
            (void*)cqufs, (void*)cfg, cfg->context,
            (void*)(uintptr_t)cfg->read, (void*)(uintptr_t)cfg->prog,
            (void*)(uintptr_t)cfg->erase, (void*)(uintptr_t)cfg->sync,
            cfg->read_size, cfg->prog_size, cfg->block_size, cfg->block_count,
            cfg->block_cycles, cfg->cache_size, cfg->lookahead_size,
            cfg->read_buffer, cfg->prog_buffer, cfg->lookahead_buffer,
            cfg->name_max, cfg->file_max, cfg->attr_max);

    err = cqufs_rawformat(cqufs, cfg);

    CQUFS_TRACE("cqufs_format -> %d", err);
    CQUFS_UNLOCK(cfg);
    return err;
}
#endif

int cqufs_mount(cqufs_t *cqufs, const struct cqufs_config *cfg) {
    int err = CQUFS_LOCK(cfg);
    if (err) {
        return err;
    }
    CQUFS_TRACE("cqufs_mount(%p, %p {.context=%p, "
                ".read=%p, .prog=%p, .erase=%p, .sync=%p, "
                ".read_size=%"PRIu32", .prog_size=%"PRIu32", "
                ".block_size=%"PRIu32", .block_count=%"PRIu32", "
                ".block_cycles=%"PRIu32", .cache_size=%"PRIu32", "
                ".lookahead_size=%"PRIu32", .read_buffer=%p, "
                ".prog_buffer=%p, .lookahead_buffer=%p, "
                ".name_max=%"PRIu32", .file_max=%"PRIu32", "
                ".attr_max=%"PRIu32"})",
            (void*)cqufs, (void*)cfg, cfg->context,
            (void*)(uintptr_t)cfg->read, (void*)(uintptr_t)cfg->prog,
            (void*)(uintptr_t)cfg->erase, (void*)(uintptr_t)cfg->sync,
            cfg->read_size, cfg->prog_size, cfg->block_size, cfg->block_count,
            cfg->block_cycles, cfg->cache_size, cfg->lookahead_size,
            cfg->read_buffer, cfg->prog_buffer, cfg->lookahead_buffer,
            cfg->name_max, cfg->file_max, cfg->attr_max);

    printf("before cqufs_rawmount -------------------\n");
    err = cqufs_rawmount(cqufs, cfg);
    printf("after cqufs_rawmount -------------------\n");
    CQUFS_TRACE("cqufs_mount -> %d", err);
    CQUFS_UNLOCK(cfg);
    return err;
}

int cqufs_unmount(cqufs_t *cqufs) {
    int err = CQUFS_LOCK(cqufs->cfg);
    if (err) {
        return err;
    }
    CQUFS_TRACE("cqufs_unmount(%p)", (void*)cqufs);

    err = cqufs_rawunmount(cqufs);

    CQUFS_TRACE("cqufs_unmount -> %d", err);
    CQUFS_UNLOCK(cqufs->cfg);
    return err;
}

#ifndef CQUFS_READONLY
int cqufs_remove(cqufs_t *cqufs, const char *path) {
    int err = CQUFS_LOCK(cqufs->cfg);
    if (err) {
        return err;
    }
    CQUFS_TRACE("cqufs_remove(%p, \"%s\")", (void*)cqufs, path);

    err = cqufs_rawremove(cqufs, path);

    CQUFS_TRACE("cqufs_remove -> %d", err);
    CQUFS_UNLOCK(cqufs->cfg);
    return err;
}
#endif

#ifndef CQUFS_READONLY
int cqufs_rename(cqufs_t *cqufs, const char *oldpath, const char *newpath) {
    int err = CQUFS_LOCK(cqufs->cfg);
    if (err) {
        return err;
    }
    CQUFS_TRACE("cqufs_rename(%p, \"%s\", \"%s\")", (void*)cqufs, oldpath, newpath);

    err = cqufs_rawrename(cqufs, oldpath, newpath);

    CQUFS_TRACE("cqufs_rename -> %d", err);
    CQUFS_UNLOCK(cqufs->cfg);
    return err;
}
#endif

int cqufs_stat(cqufs_t *cqufs, const char *path, struct cqufs_info *info) {
    int err = CQUFS_LOCK(cqufs->cfg);
    if (err) {
        return err;
    }
    CQUFS_TRACE("cqufs_stat(%p, \"%s\", %p)", (void*)cqufs, path, (void*)info);

    err = cqufs_rawstat(cqufs, path, info);

    CQUFS_TRACE("cqufs_stat -> %d", err);
    CQUFS_UNLOCK(cqufs->cfg);
    return err;
}

cqufs_ssize_t cqufs_getattr(cqufs_t *cqufs, const char *path,
        uint8_t type, void *buffer, cqufs_size_t size) {
    int err = CQUFS_LOCK(cqufs->cfg);
    if (err) {
        return err;
    }
    CQUFS_TRACE("cqufs_getattr(%p, \"%s\", %"PRIu8", %p, %"PRIu32")",
            (void*)cqufs, path, type, buffer, size);

    cqufs_ssize_t res = cqufs_rawgetattr(cqufs, path, type, buffer, size);

    CQUFS_TRACE("cqufs_getattr -> %"PRId32, res);
    CQUFS_UNLOCK(cqufs->cfg);
    return res;
}

#ifndef CQUFS_READONLY
int cqufs_setattr(cqufs_t *cqufs, const char *path,
        uint8_t type, const void *buffer, cqufs_size_t size) {
    int err = CQUFS_LOCK(cqufs->cfg);
    if (err) {
        return err;
    }
    CQUFS_TRACE("cqufs_setattr(%p, \"%s\", %"PRIu8", %p, %"PRIu32")",
            (void*)cqufs, path, type, buffer, size);

    err = cqufs_rawsetattr(cqufs, path, type, buffer, size);

    CQUFS_TRACE("cqufs_setattr -> %d", err);
    CQUFS_UNLOCK(cqufs->cfg);
    return err;
}
#endif

#ifndef CQUFS_READONLY
int cqufs_removeattr(cqufs_t *cqufs, const char *path, uint8_t type) {
    int err = CQUFS_LOCK(cqufs->cfg);
    if (err) {
        return err;
    }
    CQUFS_TRACE("cqufs_removeattr(%p, \"%s\", %"PRIu8")", (void*)cqufs, path, type);

    err = cqufs_rawremoveattr(cqufs, path, type);

    CQUFS_TRACE("cqufs_removeattr -> %d", err);
    CQUFS_UNLOCK(cqufs->cfg);
    return err;
}
#endif

#ifndef CQUFS_NO_MALLOC
int cqufs_file_open(cqufs_t *cqufs, cqufs_file_t *file, const char *path, int flags) {
    int err = CQUFS_LOCK(cqufs->cfg);
    if (err) {
        return err;
    }
    CQUFS_TRACE("cqufs_file_open(%p, %p, \"%s\", %x)",
            (void*)cqufs, (void*)file, path, flags);
    CQUFS_ASSERT(!cqufs_mlist_isopen(cqufs->mlist, (struct cqufs_mlist*)file));

    err = cqufs_file_rawopen(cqufs, file, path, flags);

    CQUFS_TRACE("cqufs_file_open -> %d", err);
    CQUFS_UNLOCK(cqufs->cfg);
    return err;
}
#endif

int cqufs_file_opencfg(cqufs_t *cqufs, cqufs_file_t *file,
        const char *path, int flags,
        const struct cqufs_file_config *cfg) {
    int err = CQUFS_LOCK(cqufs->cfg);
    if (err) {
        return err;
    }
    CQUFS_TRACE("cqufs_file_opencfg(%p, %p, \"%s\", %x, %p {"
                 ".buffer=%p, .attrs=%p, .attr_count=%"PRIu32"})",
            (void*)cqufs, (void*)file, path, flags,
            (void*)cfg, cfg->buffer, (void*)cfg->attrs, cfg->attr_count);
    CQUFS_ASSERT(!cqufs_mlist_isopen(cqufs->mlist, (struct cqufs_mlist*)file));

    err = cqufs_file_rawopencfg(cqufs, file, path, flags, cfg);

    CQUFS_TRACE("cqufs_file_opencfg -> %d", err);
    CQUFS_UNLOCK(cqufs->cfg);
    return err;
}

int cqufs_file_close(cqufs_t *cqufs, cqufs_file_t *file) {
    int err = CQUFS_LOCK(cqufs->cfg);
    if (err) {
        return err;
    }
    CQUFS_TRACE("cqufs_file_close(%p, %p)", (void*)cqufs, (void*)file);
    CQUFS_ASSERT(cqufs_mlist_isopen(cqufs->mlist, (struct cqufs_mlist*)file));

    err = cqufs_file_rawclose(cqufs, file);

    CQUFS_TRACE("cqufs_file_close -> %d", err);
    CQUFS_UNLOCK(cqufs->cfg);
    return err;
}

#ifndef CQUFS_READONLY
int cqufs_file_sync(cqufs_t *cqufs, cqufs_file_t *file) {
    int err = CQUFS_LOCK(cqufs->cfg);
    if (err) {
        return err;
    }
    CQUFS_TRACE("cqufs_file_sync(%p, %p)", (void*)cqufs, (void*)file);
    CQUFS_ASSERT(cqufs_mlist_isopen(cqufs->mlist, (struct cqufs_mlist*)file));

    err = cqufs_file_rawsync(cqufs, file);

    CQUFS_TRACE("cqufs_file_sync -> %d", err);
    CQUFS_UNLOCK(cqufs->cfg);
    return err;
}
#endif

cqufs_ssize_t cqufs_file_read(cqufs_t *cqufs, cqufs_file_t *file,
        void *buffer, cqufs_size_t size) {
    int err = CQUFS_LOCK(cqufs->cfg);
    if (err) {
        return err;
    }
    CQUFS_TRACE("cqufs_file_read(%p, %p, %p, %"PRIu32")",
            (void*)cqufs, (void*)file, buffer, size);
    CQUFS_ASSERT(cqufs_mlist_isopen(cqufs->mlist, (struct cqufs_mlist*)file));

    cqufs_ssize_t res = cqufs_file_rawread(cqufs, file, buffer, size);

    CQUFS_TRACE("cqufs_file_read -> %"PRId32, res);
    CQUFS_UNLOCK(cqufs->cfg);
    return res;
}

#ifndef CQUFS_READONLY
cqufs_ssize_t cqufs_file_write(cqufs_t *cqufs, cqufs_file_t *file,
        const void *buffer, cqufs_size_t size) {
    int err = CQUFS_LOCK(cqufs->cfg);
    if (err) {
        return err;
    }
    CQUFS_TRACE("cqufs_file_write(%p, %p, %p, %"PRIu32")",
            (void*)cqufs, (void*)file, buffer, size);
    CQUFS_ASSERT(cqufs_mlist_isopen(cqufs->mlist, (struct cqufs_mlist*)file));

    cqufs_ssize_t res = cqufs_file_rawwrite(cqufs, file, buffer, size);

    CQUFS_TRACE("cqufs_file_write -> %"PRId32, res);
    CQUFS_UNLOCK(cqufs->cfg);
    return res;
}
#endif

cqufs_soff_t cqufs_file_seek(cqufs_t *cqufs, cqufs_file_t *file,
        cqufs_soff_t off, int whence) {
    int err = CQUFS_LOCK(cqufs->cfg);
    if (err) {
        return err;
    }
    CQUFS_TRACE("cqufs_file_seek(%p, %p, %"PRId32", %d)",
            (void*)cqufs, (void*)file, off, whence);
    CQUFS_ASSERT(cqufs_mlist_isopen(cqufs->mlist, (struct cqufs_mlist*)file));

    cqufs_soff_t res = cqufs_file_rawseek(cqufs, file, off, whence);

    CQUFS_TRACE("cqufs_file_seek -> %"PRId32, res);
    CQUFS_UNLOCK(cqufs->cfg);
    return res;
}

#ifndef CQUFS_READONLY
int cqufs_file_truncate(cqufs_t *cqufs, cqufs_file_t *file, cqufs_off_t size) {
    int err = CQUFS_LOCK(cqufs->cfg);
    if (err) {
        return err;
    }
    CQUFS_TRACE("cqufs_file_truncate(%p, %p, %"PRIu32")",
            (void*)cqufs, (void*)file, size);
    CQUFS_ASSERT(cqufs_mlist_isopen(cqufs->mlist, (struct cqufs_mlist*)file));

    err = cqufs_file_rawtruncate(cqufs, file, size);

    CQUFS_TRACE("cqufs_file_truncate -> %d", err);
    CQUFS_UNLOCK(cqufs->cfg);
    return err;
}
#endif

cqufs_soff_t cqufs_file_tell(cqufs_t *cqufs, cqufs_file_t *file) {
    int err = CQUFS_LOCK(cqufs->cfg);
    if (err) {
        return err;
    }
    CQUFS_TRACE("cqufs_file_tell(%p, %p)", (void*)cqufs, (void*)file);
    CQUFS_ASSERT(cqufs_mlist_isopen(cqufs->mlist, (struct cqufs_mlist*)file));

    cqufs_soff_t res = cqufs_file_rawtell(cqufs, file);

    CQUFS_TRACE("cqufs_file_tell -> %"PRId32, res);
    CQUFS_UNLOCK(cqufs->cfg);
    return res;
}

int cqufs_file_rewind(cqufs_t *cqufs, cqufs_file_t *file) {
    int err = CQUFS_LOCK(cqufs->cfg);
    if (err) {
        return err;
    }
    CQUFS_TRACE("cqufs_file_rewind(%p, %p)", (void*)cqufs, (void*)file);

    err = cqufs_file_rawrewind(cqufs, file);

    CQUFS_TRACE("cqufs_file_rewind -> %d", err);
    CQUFS_UNLOCK(cqufs->cfg);
    return err;
}

cqufs_soff_t cqufs_file_size(cqufs_t *cqufs, cqufs_file_t *file) {
    int err = CQUFS_LOCK(cqufs->cfg);
    if (err) {
        return err;
    }
    CQUFS_TRACE("cqufs_file_size(%p, %p)", (void*)cqufs, (void*)file);
    CQUFS_ASSERT(cqufs_mlist_isopen(cqufs->mlist, (struct cqufs_mlist*)file));

    cqufs_soff_t res = cqufs_file_rawsize(cqufs, file);

    CQUFS_TRACE("cqufs_file_size -> %"PRId32, res);
    CQUFS_UNLOCK(cqufs->cfg);
    return res;
}

#ifndef CQUFS_READONLY
int cqufs_mkdir(cqufs_t *cqufs, const char *path) {
    int err = CQUFS_LOCK(cqufs->cfg);
    if (err) {
        return err;
    }
    CQUFS_TRACE("cqufs_mkdir(%p, \"%s\")", (void*)cqufs, path);

    err = cqufs_rawmkdir(cqufs, path);

    CQUFS_TRACE("cqufs_mkdir -> %d", err);
    CQUFS_UNLOCK(cqufs->cfg);
    return err;
}
#endif

int cqufs_dir_open(cqufs_t *cqufs, cqufs_dir_t *dir, const char *path) {
    int err = CQUFS_LOCK(cqufs->cfg);
    if (err) {
        return err;
    }
    CQUFS_TRACE("cqufs_dir_open(%p, %p, \"%s\")", (void*)cqufs, (void*)dir, path);
    CQUFS_ASSERT(!cqufs_mlist_isopen(cqufs->mlist, (struct cqufs_mlist*)dir));

    err = cqufs_dir_rawopen(cqufs, dir, path);

    CQUFS_TRACE("cqufs_dir_open -> %d", err);
    CQUFS_UNLOCK(cqufs->cfg);
    return err;
}

int cqufs_dir_close(cqufs_t *cqufs, cqufs_dir_t *dir) {
    int err = CQUFS_LOCK(cqufs->cfg);
    if (err) {
        return err;
    }
    CQUFS_TRACE("cqufs_dir_close(%p, %p)", (void*)cqufs, (void*)dir);

    err = cqufs_dir_rawclose(cqufs, dir);

    CQUFS_TRACE("cqufs_dir_close -> %d", err);
    CQUFS_UNLOCK(cqufs->cfg);
    return err;
}

int cqufs_dir_read(cqufs_t *cqufs, cqufs_dir_t *dir, struct cqufs_info *info) {
    int err = CQUFS_LOCK(cqufs->cfg);
    if (err) {
        return err;
    }
    CQUFS_TRACE("cqufs_dir_read(%p, %p, %p)",
            (void*)cqufs, (void*)dir, (void*)info);

    err = cqufs_dir_rawread(cqufs, dir, info);

    CQUFS_TRACE("cqufs_dir_read -> %d", err);
    CQUFS_UNLOCK(cqufs->cfg);
    return err;
}

int cqufs_dir_seek(cqufs_t *cqufs, cqufs_dir_t *dir, cqufs_off_t off) {
    int err = CQUFS_LOCK(cqufs->cfg);
    if (err) {
        return err;
    }
    CQUFS_TRACE("cqufs_dir_seek(%p, %p, %"PRIu32")",
            (void*)cqufs, (void*)dir, off);

    err = cqufs_dir_rawseek(cqufs, dir, off);

    CQUFS_TRACE("cqufs_dir_seek -> %d", err);
    CQUFS_UNLOCK(cqufs->cfg);
    return err;
}

cqufs_soff_t cqufs_dir_tell(cqufs_t *cqufs, cqufs_dir_t *dir) {
    int err = CQUFS_LOCK(cqufs->cfg);
    if (err) {
        return err;
    }
    CQUFS_TRACE("cqufs_dir_tell(%p, %p)", (void*)cqufs, (void*)dir);

    cqufs_soff_t res = cqufs_dir_rawtell(cqufs, dir);

    CQUFS_TRACE("cqufs_dir_tell -> %"PRId32, res);
    CQUFS_UNLOCK(cqufs->cfg);
    return res;
}

int cqufs_dir_rewind(cqufs_t *cqufs, cqufs_dir_t *dir) {
    int err = CQUFS_LOCK(cqufs->cfg);
    if (err) {
        return err;
    }
    CQUFS_TRACE("cqufs_dir_rewind(%p, %p)", (void*)cqufs, (void*)dir);

    err = cqufs_dir_rawrewind(cqufs, dir);

    CQUFS_TRACE("cqufs_dir_rewind -> %d", err);
    CQUFS_UNLOCK(cqufs->cfg);
    return err;
}

cqufs_ssize_t cqufs_fs_size(cqufs_t *cqufs) {
    int err = CQUFS_LOCK(cqufs->cfg);
    if (err) {
        return err;
    }
    CQUFS_TRACE("cqufs_fs_size(%p)", (void*)cqufs);

    cqufs_ssize_t res = cqufs_fs_rawsize(cqufs);

    CQUFS_TRACE("cqufs_fs_size -> %"PRId32, res);
    CQUFS_UNLOCK(cqufs->cfg);
    return res;
}

int cqufs_fs_traverse(cqufs_t *cqufs, int (*cb)(void *, cqufs_block_t), void *data) {
    int err = CQUFS_LOCK(cqufs->cfg);
    if (err) {
        return err;
    }
    CQUFS_TRACE("cqufs_fs_traverse(%p, %p, %p)",
            (void*)cqufs, (void*)(uintptr_t)cb, data);

    err = cqufs_fs_rawtraverse(cqufs, cb, data, true);

    CQUFS_TRACE("cqufs_fs_traverse -> %d", err);
    CQUFS_UNLOCK(cqufs->cfg);
    return err;
}

#ifdef CQUFS_MIGRATE
int cqufs_migrate(cqufs_t *cqufs, const struct cqufs_config *cfg) {
    int err = CQUFS_LOCK(cfg);
    if (err) {
        return err;
    }
    CQUFS_TRACE("cqufs_migrate(%p, %p {.context=%p, "
                ".read=%p, .prog=%p, .erase=%p, .sync=%p, "
                ".read_size=%"PRIu32", .prog_size=%"PRIu32", "
                ".block_size=%"PRIu32", .block_count=%"PRIu32", "
                ".block_cycles=%"PRIu32", .cache_size=%"PRIu32", "
                ".lookahead_size=%"PRIu32", .read_buffer=%p, "
                ".prog_buffer=%p, .lookahead_buffer=%p, "
                ".name_max=%"PRIu32", .file_max=%"PRIu32", "
                ".attr_max=%"PRIu32"})",
            (void*)cqufs, (void*)cfg, cfg->context,
            (void*)(uintptr_t)cfg->read, (void*)(uintptr_t)cfg->prog,
            (void*)(uintptr_t)cfg->erase, (void*)(uintptr_t)cfg->sync,
            cfg->read_size, cfg->prog_size, cfg->block_size, cfg->block_count,
            cfg->block_cycles, cfg->cache_size, cfg->lookahead_size,
            cfg->read_buffer, cfg->prog_buffer, cfg->lookahead_buffer,
            cfg->name_max, cfg->file_max, cfg->attr_max);

    err = cqufs_rawmigrate(cqufs, cfg);

    CQUFS_TRACE("cqufs_migrate -> %d", err);
    CQUFS_UNLOCK(cfg);
    return err;
}
#endif

