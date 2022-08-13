
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
** 文   件   名: clfs.c
**
** 创   建   人: 章俊文
**
** 文件创建日期: 2022 年 06 月 04 日
**
** 描        述: clfs实现文件
*********************************************************************************************************/
#include "clfs.h"
#include "clfs_util.h"

/*********************************************************************************************************
  代码中使用的一些常量
*********************************************************************************************************/
#define CLFS_BLOCK_NULL ((clfs_block_t)-1)
#define CLFS_BLOCK_INLINE ((clfs_block_t)-2)

enum {
    CLFS_OK_RELOCATED = 1,
    CLFS_OK_DROPPED   = 2,
    CLFS_OK_ORPHANED  = 3,
};

enum {
    CLFS_CMP_EQ = 0,
    CLFS_CMP_LT = 1,
    CLFS_CMP_GT = 2,
};

/*********************************************************************************************************
  缓存块设备操作
*********************************************************************************************************/

// 取消一个cache
static inline void clfs_cache_drop(clfs_t *clfs, clfs_cache_t *rcache) {
    /* 不要为零，如果缓存是只读的或只会是只读的，开销更小，用相同的数据写入(在重新定位期间) */
    (void)clfs;
    rcache->block = CLFS_BLOCK_NULL;
}

// 填充零，避免信息泄露
static inline void clfs_cache_zero(clfs_t *clfs, clfs_cache_t *pcache) {
    memset(pcache->buffer, 0xff, clfs->cfg->cache_size);
    pcache->block = CLFS_BLOCK_NULL;
}

// 从设备读取数据
static int clfs_bd_read(clfs_t *clfs,
        const clfs_cache_t *pcache, clfs_cache_t *rcache, clfs_size_t hint,
        clfs_block_t block, clfs_off_t off,
        void *buffer, clfs_size_t size) {
    uint8_t *data = buffer;
    if (block >= clfs->cfg->block_count ||
            off+size > clfs->cfg->block_size) {
        return CLFS_ERR_CORRUPT;
    }

    while (size > 0) {
        clfs_size_t diff = size;

        if (pcache && block == pcache->block &&
                off < pcache->off + pcache->size) {
            if (off >= pcache->off) { /*  已经在pcache中？   */
                diff = clfs_min(diff, pcache->size - (off-pcache->off));
                memcpy(data, &pcache->buffer[off-pcache->off], diff);

                data += diff;
                off += diff;
                size -= diff;
                continue;
            }

            diff = clfs_min(diff, pcache->off-off); /*  pcache优先读   */
        }

        if (block == rcache->block &&
                off < rcache->off + rcache->size) {
            if (off >= rcache->off) { /*  已经在rcache中？   */
                diff = clfs_min(diff, rcache->size - (off-rcache->off));
                memcpy(data, &rcache->buffer[off-rcache->off], diff);

                data += diff;
                off += diff;
                size -= diff;
                continue;
            }

            diff = clfs_min(diff, rcache->off-off);/*  rcache优先读   */
        }

        if (size >= hint && off % clfs->cfg->read_size == 0 &&
                size >= clfs->cfg->read_size) {    /*  不在cache中，且一个cache装不下    */

            diff = clfs_aligndown(diff, clfs->cfg->read_size);
            int err = clfs->cfg->read(clfs->cfg, block, off, data, diff);
            if (err) {
                return err;
            }

            data += diff;
            off += diff;
            size -= diff;
            continue;
        }

        CLFS_ASSERT(block < clfs->cfg->block_count); /*  加载到缓存，第一个条件不能再失败   */
        rcache->block = block;
        rcache->off = clfs_aligndown(off, clfs->cfg->read_size);
        rcache->size = clfs_min(
                clfs_min(
                    clfs_alignup(off+hint, clfs->cfg->read_size),
                    clfs->cfg->block_size)
                - rcache->off,
                clfs->cfg->cache_size);
        int err = clfs->cfg->read(clfs->cfg, rcache->block,
                rcache->off, rcache->buffer, rcache->size);
        CLFS_ASSERT(err <= 0);
        if (err) {
            return err;
        }
    }

    return 0;
}

// 比较设备上数据
static int clfs_bd_cmp(clfs_t *clfs,
        const clfs_cache_t *pcache, clfs_cache_t *rcache, clfs_size_t hint,
        clfs_block_t block, clfs_off_t off,
        const void *buffer, clfs_size_t size) {
    const uint8_t *data = buffer;
    clfs_size_t diff = 0;
    clfs_off_t i;

    for (i = 0; i < size; i += diff) {
        uint8_t dat[8];

        diff = clfs_min(size-i, sizeof(dat));
        int res = clfs_bd_read(clfs,
                pcache, rcache, hint-i,
                block, off+i, &dat, diff);
        if (res) {
            return res;
        }

        res = memcmp(dat, data + i, diff);
        if (res) {
            return res < 0 ? CLFS_CMP_LT : CLFS_CMP_GT;
        }
    }

    return CLFS_CMP_EQ;
}

#ifndef CLFS_READONLY

// 将cache中数据刷到设备上
static int clfs_bd_flush(clfs_t *clfs,
        clfs_cache_t *pcache, clfs_cache_t *rcache, bool validate) {
    if (pcache->block != CLFS_BLOCK_NULL && pcache->block != CLFS_BLOCK_INLINE) {
        CLFS_ASSERT(pcache->block < clfs->cfg->block_count);
        clfs_size_t diff = clfs_alignup(pcache->size, clfs->cfg->prog_size);
        int err = clfs->cfg->prog(clfs->cfg, pcache->block,
                pcache->off, pcache->buffer, diff);
        CLFS_ASSERT(err <= 0);
        if (err) {
            return err;
        }

        if (validate) { /* 检查磁盘上的数据 */
            clfs_cache_drop(clfs, rcache);
            int res = clfs_bd_cmp(clfs,
                    NULL, rcache, diff,
                    pcache->block, pcache->off, pcache->buffer, diff);
            if (res < 0) {
                return res;
            }

            if (res != CLFS_CMP_EQ) {
                return CLFS_ERR_CORRUPT;
            }
        }

        clfs_cache_zero(clfs, pcache);
    }

    return 0;
}
#endif

#ifndef CLFS_READONLY

// 同步设备上数据
static int clfs_bd_sync(clfs_t *clfs,
        clfs_cache_t *pcache, clfs_cache_t *rcache, bool validate) {
    clfs_cache_drop(clfs, rcache);

    int err = clfs_bd_flush(clfs, pcache, rcache, validate);
    if (err) {
        return err;
    }

    err = clfs->cfg->sync(clfs->cfg);
    CLFS_ASSERT(err <= 0);
    return err;
}
#endif

#ifndef CLFS_READONLY

// 像设备写入数据
static int clfs_bd_prog(clfs_t *clfs,
        clfs_cache_t *pcache, clfs_cache_t *rcache, bool validate,
        clfs_block_t block, clfs_off_t off,
        const void *buffer, clfs_size_t size) {
    const uint8_t *data = buffer;
    CLFS_ASSERT(block == CLFS_BLOCK_INLINE || block < clfs->cfg->block_count);
    CLFS_ASSERT(off + size <= clfs->cfg->block_size);

    while (size > 0) {
        if (block == pcache->block &&
                off >= pcache->off &&
                off < pcache->off + clfs->cfg->cache_size) { /* 是否已经在pcache */
            clfs_size_t diff = clfs_min(size,
                    clfs->cfg->cache_size - (off-pcache->off));
            memcpy(&pcache->buffer[off-pcache->off], data, diff);

            data += diff;
            off += diff;
            size -= diff;

            pcache->size = clfs_max(pcache->size, off - pcache->off);
            if (pcache->size == clfs->cfg->cache_size) {
                /* 如果填满了，就会立马flush pcache */
                int err = clfs_bd_flush(clfs, pcache, rcache, validate);
                if (err) {
                    return err;
                }
            }

            continue;
        }

        /* pcache必须被flush，通过programming或者整个块手动flush */
        CLFS_ASSERT(pcache->block == CLFS_BLOCK_NULL);

        pcache->block = block; /* 准备pcache，第一个条件不能再失败 */
        pcache->off = clfs_aligndown(off, clfs->cfg->prog_size);
        pcache->size = 0;
    }

    return 0;
}
#endif

#ifndef CLFS_READONLY
static int clfs_bd_erase(clfs_t *clfs, clfs_block_t block) {
    CLFS_ASSERT(block < clfs->cfg->block_count);
    int err = clfs->cfg->erase(clfs->cfg, block);
    CLFS_ASSERT(err <= 0);
    return err;
}
#endif


/*********************************************************************************************************
  ClFs实用工具
*********************************************************************************************************/
/* 在块对上的操作 */
static inline void clfs_pair_swap(clfs_block_t pair[2]) {
    clfs_block_t t = pair[0];
    pair[0] = pair[1];
    pair[1] = t;
}

static inline bool clfs_pair_isnull(const clfs_block_t pair[2]) {
    return pair[0] == CLFS_BLOCK_NULL || pair[1] == CLFS_BLOCK_NULL;
}

static inline int clfs_pair_cmp(
        const clfs_block_t paira[2],
        const clfs_block_t pairb[2]) {
    return !(paira[0] == pairb[0] || paira[1] == pairb[1] ||
             paira[0] == pairb[1] || paira[1] == pairb[0]);
}

#ifndef CLFS_READONLY
static inline bool clfs_pair_sync(
        const clfs_block_t paira[2],
        const clfs_block_t pairb[2]) {
    return (paira[0] == pairb[0] && paira[1] == pairb[1]) ||
           (paira[0] == pairb[1] && paira[1] == pairb[0]);
}
#endif

static inline void clfs_pair_fromle32(clfs_block_t pair[2]) {
    pair[0] = clfs_fromle32(pair[0]);
    pair[1] = clfs_fromle32(pair[1]);
}

#ifndef CLFS_READONLY
static inline void clfs_pair_tole32(clfs_block_t pair[2]) {
    pair[0] = clfs_tole32(pair[0]);
    pair[1] = clfs_tole32(pair[1]);
}
#endif
/* 对32位entry tags的操作 */
typedef uint32_t clfs_tag_t;
typedef int32_t clfs_stag_t;

#define CLFS_MKTAG(type, id, size) \
    (((clfs_tag_t)(type) << 20) | ((clfs_tag_t)(id) << 10) | (clfs_tag_t)(size))

#define CLFS_MKTAG_IF(cond, type, id, size) \
    ((cond) ? CLFS_MKTAG(type, id, size) : CLFS_MKTAG(CLFS_FROM_NOOP, 0, 0))

#define CLFS_MKTAG_IF_ELSE(cond, type1, id1, size1, type2, id2, size2) \
    ((cond) ? CLFS_MKTAG(type1, id1, size1) : CLFS_MKTAG(type2, id2, size2))

static inline bool clfs_tag_isvalid(clfs_tag_t tag) {
    return !(tag & 0x80000000);
}

static inline bool clfs_tag_isdelete(clfs_tag_t tag) {
    return ((int32_t)(tag << 22) >> 22) == -1;
}

static inline uint16_t clfs_tag_type1(clfs_tag_t tag) {
    return (tag & 0x70000000) >> 20;
}

static inline uint16_t clfs_tag_type3(clfs_tag_t tag) {
    return (tag & 0x7ff00000) >> 20;
}

static inline uint8_t clfs_tag_chunk(clfs_tag_t tag) {
    return (tag & 0x0ff00000) >> 20;
}

static inline int8_t clfs_tag_splice(clfs_tag_t tag) {
    return (int8_t)clfs_tag_chunk(tag);
}

static inline uint16_t clfs_tag_id(clfs_tag_t tag) {
    return (tag & 0x000ffc00) >> 10;
}

static inline clfs_size_t clfs_tag_size(clfs_tag_t tag) {
    return tag & 0x000003ff;
}

static inline clfs_size_t clfs_tag_dsize(clfs_tag_t tag) {
    return sizeof(tag) + clfs_tag_size(tag + clfs_tag_isdelete(tag));
}
/* 对属性列表中属性的操作 */
struct clfs_mattr {
    clfs_tag_t tag;
    const void *buffer;
};

struct clfs_diskoff {
    clfs_block_t block;
    clfs_off_t off;
};

#define CLFS_MKATTRS(...) \
    (struct clfs_mattr[]){__VA_ARGS__}, \
    sizeof((struct clfs_mattr[]){__VA_ARGS__}) / sizeof(struct clfs_mattr)

/* 对全局状态的操作 */
static inline void clfs_gstate_xor(clfs_gstate_t *a, const clfs_gstate_t *b) {
    int i;
    for (i = 0; i < 3; i++) {
        ((uint32_t*)a)[i] ^= ((const uint32_t*)b)[i];
    }
}

static inline bool clfs_gstate_iszero(const clfs_gstate_t *a) {
    int i;
    for (i = 0; i < 3; i++) {
        if (((uint32_t*)a)[i] != 0) {
            return false;
        }
    }
    return true;
}

#ifndef CLFS_READONLY
static inline bool clfs_gstate_hasorphans(const clfs_gstate_t *a) {
    return clfs_tag_size(a->tag);
}

static inline uint8_t clfs_gstate_getorphans(const clfs_gstate_t *a) {
    return clfs_tag_size(a->tag);
}

static inline bool clfs_gstate_hasmove(const clfs_gstate_t *a) {
    return clfs_tag_type1(a->tag);
}
#endif

static inline bool clfs_gstate_hasmovehere(const clfs_gstate_t *a,
        const clfs_block_t *pair) {
    return clfs_tag_type1(a->tag) && clfs_pair_cmp(a->pair, pair) == 0;
}

static inline void clfs_gstate_fromle32(clfs_gstate_t *a) {
    a->tag     = clfs_fromle32(a->tag);
    a->pair[0] = clfs_fromle32(a->pair[0]);
    a->pair[1] = clfs_fromle32(a->pair[1]);
}

#ifndef CLFS_READONLY
static inline void clfs_gstate_tole32(clfs_gstate_t *a) {
    a->tag     = clfs_tole32(a->tag);
    a->pair[0] = clfs_tole32(a->pair[0]);
    a->pair[1] = clfs_tole32(a->pair[1]);
}
#endif

/* 其他字节顺序操作 */
static void clfs_ctz_fromle32(struct clfs_ctz *ctz) {
    ctz->head = clfs_fromle32(ctz->head);
    ctz->size = clfs_fromle32(ctz->size);
}

#ifndef CLFS_READONLY
static void clfs_ctz_tole32(struct clfs_ctz *ctz) {
    ctz->head = clfs_tole32(ctz->head);
    ctz->size = clfs_tole32(ctz->size);
}
#endif

static inline void clfs_superblock_fromle32(clfs_superblock_t *superblock) {
    superblock->version     = clfs_fromle32(superblock->version);
    superblock->block_size  = clfs_fromle32(superblock->block_size);
    superblock->block_count = clfs_fromle32(superblock->block_count);
    superblock->name_max    = clfs_fromle32(superblock->name_max);
    superblock->file_max    = clfs_fromle32(superblock->file_max);
    superblock->attr_max    = clfs_fromle32(superblock->attr_max);
}

#ifndef CLFS_READONLY
static inline void clfs_superblock_tole32(clfs_superblock_t *superblock) {
    superblock->version     = clfs_tole32(superblock->version);
    superblock->block_size  = clfs_tole32(superblock->block_size);
    superblock->block_count = clfs_tole32(superblock->block_count);
    superblock->name_max    = clfs_tole32(superblock->name_max);
    superblock->file_max    = clfs_tole32(superblock->file_max);
    superblock->attr_max    = clfs_tole32(superblock->attr_max);
}
#endif

#ifndef CLFS_NO_ASSERT
// 文件节点是否在打开文件链表里
static bool clfs_mlist_isopen(struct clfs_mlist *head,
        struct clfs_mlist *node) {
    struct clfs_mlist **p;
    for (p = &head; *p; p = &(*p)->next) {
        if (*p == (struct clfs_mlist*)node) {
            return true;
        }
    }

    return false;
}
#endif

// 文件节点是否已从打开文件链表中删除
static void clfs_mlist_remove(clfs_t *clfs, struct clfs_mlist *mlist) {
    struct clfs_mlist **p;
    for (p = &clfs->mlist; *p; p = &(*p)->next) {
        if (*p == mlist) {
            *p = (*p)->next;
            break;
        }
    }
}

// 在打开文件来年表中加入该节点
static void clfs_mlist_append(clfs_t *clfs, struct clfs_mlist *mlist) {
    mlist->next = clfs->mlist;
    clfs->mlist = mlist;
}

/*********************************************************************************************************
  预先声明的内部操作
*********************************************************************************************************/
#ifndef CLFS_READONLY
static int clfs_dir_commit(clfs_t *clfs, clfs_mdir_t *dir,
        const struct clfs_mattr *attrs, int attrcount);
static int clfs_dir_compact(clfs_t *clfs,
        clfs_mdir_t *dir, const struct clfs_mattr *attrs, int attrcount,
        clfs_mdir_t *source, uint16_t begin, uint16_t end);
static clfs_ssize_t clfs_file_flushedwrite(clfs_t *clfs, clfs_file_t *file,
        const void *buffer, clfs_size_t size);
static clfs_ssize_t clfs_file_rawwrite(clfs_t *clfs, clfs_file_t *file,
        const void *buffer, clfs_size_t size);
static int clfs_file_rawsync(clfs_t *clfs, clfs_file_t *file);
static int clfs_file_outline(clfs_t *clfs, clfs_file_t *file);
static int clfs_file_flush(clfs_t *clfs, clfs_file_t *file);

static int clfs_fs_deorphan(clfs_t *clfs, bool powerloss);
static int clfs_fs_preporphans(clfs_t *clfs, int8_t orphans);
static void clfs_fs_prepmove(clfs_t *clfs,
        uint16_t id, const clfs_block_t pair[2]);
static int clfs_fs_pred(clfs_t *clfs, const clfs_block_t dir[2],
        clfs_mdir_t *pdir);
static clfs_stag_t clfs_fs_parent(clfs_t *clfs, const clfs_block_t dir[2],
        clfs_mdir_t *parent);
static int clfs_fs_forceconsistency(clfs_t *clfs);
#endif

#ifdef CLFS_MIGRATE
static int clfs1_traverse(clfs_t *clfs,
        int (*cb)(void*, clfs_block_t), void *data);
#endif

static int clfs_dir_rawrewind(clfs_t *clfs, clfs_dir_t *dir);

static clfs_ssize_t clfs_file_flushedread(clfs_t *clfs, clfs_file_t *file,
        void *buffer, clfs_size_t size);
static clfs_ssize_t clfs_file_rawread(clfs_t *clfs, clfs_file_t *file,
        void *buffer, clfs_size_t size);
static int clfs_file_rawclose(clfs_t *clfs, clfs_file_t *file);
static clfs_soff_t clfs_file_rawsize(clfs_t *clfs, clfs_file_t *file);

static clfs_ssize_t clfs_fs_rawsize(clfs_t *clfs);
static int clfs_fs_rawtraverse(clfs_t *clfs,
        int (*cb)(void *data, clfs_block_t block), void *data,
        bool includeorphans);

static int clfs_deinit(clfs_t *clfs);
static int clfs_rawunmount(clfs_t *clfs);

/*********************************************************************************************************
  块分配器
*********************************************************************************************************/
#ifndef CLFS_READONLY

// 块分配器初始化
static int clfs_alloc_lookahead(void *p, clfs_block_t block) {
    clfs_t *clfs = (clfs_t*)p;
    clfs_block_t off = ((block - clfs->free.off)
            + clfs->cfg->block_count) % clfs->cfg->block_count;

    if (off < clfs->free.size) {
        clfs->free.buffer[off / 32] |= 1U << (off % 32);
    }

    return 0;
}
#endif

// 表明已分配的块已提交到文件系统，这是为了防止块在提交操作过程中被垃圾收集
static void clfs_alloc_ack(clfs_t *clfs) {
    clfs->free.ack = clfs->cfg->block_count;
}

// 删除前向缓冲区，这是在挂载和失败的遍历期间做的，以避免无效的lookahead
static void clfs_alloc_drop(clfs_t *clfs) {
    clfs->free.size = 0;
    clfs->free.i = 0;
    clfs_alloc_ack(clfs);
}

#ifndef CLFS_READONLY

// 分配一个块
static int clfs_alloc(clfs_t *clfs, clfs_block_t *block) {
    while (true) {
        while (clfs->free.i != clfs->free.size) {
            clfs_block_t off = clfs->free.i;
            clfs->free.i += 1;
            clfs->free.ack -= 1;

            if (!(clfs->free.buffer[off / 32] & (1U << (off % 32)))) {
                *block = (clfs->free.off + off) % clfs->cfg->block_count;
                /* 找到一个空闲的块 */
                while (clfs->free.i != clfs->free.size &&
                        (clfs->free.buffer[clfs->free.i / 32]
                            & (1U << (clfs->free.i % 32)))) {
                    /*立马寻找下一个off处使得alloc ack可以discredit旧的lookahead block */
                    clfs->free.i += 1;
                    clfs->free.ack -= 1;
                }

                return 0;
            }
        }

        if (clfs->free.ack == 0) {
            /* 检查我们是否查看了自上次ack以来的所有块 */
            CLFS_ERROR("No more free space %"PRIu32,
                    clfs->free.i + clfs->free.off);
            return CLFS_ERR_NOSPC;
        }

        clfs->free.off = (clfs->free.off + clfs->free.size)
                % clfs->cfg->block_count;
        clfs->free.size = clfs_min(8*clfs->cfg->lookahead_size, clfs->free.ack);
        clfs->free.i = 0;

        memset(clfs->free.buffer, 0, clfs->cfg->lookahead_size);
        /* 从tree中找到空闲块的掩码 */
        int err = clfs_fs_rawtraverse(clfs, clfs_alloc_lookahead, clfs, true);
        if (err) {
            clfs_alloc_drop(clfs);
            return err;
        }
    }
}
#endif


/*********************************************************************************************************
  元数据对和目录操作
*********************************************************************************************************/
static clfs_stag_t clfs_dir_getslice(clfs_t *clfs, const clfs_mdir_t *dir,
        clfs_tag_t gmask, clfs_tag_t gtag,
        clfs_off_t goff, void *gbuffer, clfs_size_t gsize) {
    clfs_off_t off = dir->off;
    clfs_tag_t ntag = dir->etag;
    clfs_stag_t gdiff = 0;

    if (clfs_gstate_hasmovehere(&clfs->gdisk, dir->pair) &&
            clfs_tag_id(gmask) != 0 &&
            clfs_tag_id(clfs->gdisk.tag) <= clfs_tag_id(gtag)) {
        gdiff -= CLFS_MKTAG(0, 1, 0);  /* 合成动作 */
    }

    while (off >= sizeof(clfs_tag_t) + clfs_tag_dsize(ntag)) {
        /* 向后遍历dir块(加快查找速度) */
        off -= clfs_tag_dsize(ntag);
        clfs_tag_t tag = ntag;
        int err = clfs_bd_read(clfs,
                NULL, &clfs->rcache, sizeof(ntag),
                dir->pair[0], off, &ntag, sizeof(ntag));
        if (err) {
            return err;
        }

        ntag = (clfs_frombe32(ntag) ^ tag) & 0x7fffffff;

        if (clfs_tag_id(gmask) != 0 &&
                clfs_tag_type1(tag) == CLFS_TYPE_SPLICE &&
                clfs_tag_id(tag) <= clfs_tag_id(gtag - gdiff)) {
            if (tag == (CLFS_MKTAG(CLFS_TYPE_CREATE, 0, 0) |
                    (CLFS_MKTAG(0, 0x3ff, 0) & (gtag - gdiff)))) {
                /* 找到发现的位置 */
                return CLFS_ERR_NOENT;
            }

            gdiff += CLFS_MKTAG(0, clfs_tag_splice(tag), 0); /* 在splices处移动 */
        }

        if ((gmask & tag) == (gmask & (gtag - gdiff))) {
            if (clfs_tag_isdelete(tag)) {
                return CLFS_ERR_NOENT;
            }

            clfs_size_t diff = clfs_min(clfs_tag_size(tag), gsize);
            err = clfs_bd_read(clfs,
                    NULL, &clfs->rcache, diff,
                    dir->pair[0], off+sizeof(tag)+goff, gbuffer, diff);
            if (err) {
                return err;
            }

            memset((uint8_t*)gbuffer + diff, 0, gsize - diff);

            return tag + gdiff;
        }
    }

    return CLFS_ERR_NOENT;
}

static clfs_stag_t clfs_dir_get(clfs_t *clfs, const clfs_mdir_t *dir,
        clfs_tag_t gmask, clfs_tag_t gtag, void *buffer) {
    return clfs_dir_getslice(clfs, dir,
            gmask, gtag,
            0, buffer, clfs_tag_size(gtag));/* 从buffer头开始找 */
}

static int clfs_dir_getread(clfs_t *clfs, const clfs_mdir_t *dir,
        const clfs_cache_t *pcache, clfs_cache_t *rcache, clfs_size_t hint,
        clfs_tag_t gmask, clfs_tag_t gtag,
        clfs_off_t off, void *buffer, clfs_size_t size) {
    uint8_t *data = buffer;
    if (off+size > clfs->cfg->block_size) {
        return CLFS_ERR_CORRUPT;
    }

    while (size > 0) {
        clfs_size_t diff = size;

        if (pcache && pcache->block == CLFS_BLOCK_INLINE &&
                off < pcache->off + pcache->size) {
            if (off >= pcache->off) {
                /* 是否已经存在在pcache  */
                diff = clfs_min(diff, pcache->size - (off-pcache->off));
                memcpy(data, &pcache->buffer[off-pcache->off], diff);

                data += diff;
                off += diff;
                size -= diff;
                continue;
            }

            diff = clfs_min(diff, pcache->off-off); /* pcache优先 */
        }

        if (rcache->block == CLFS_BLOCK_INLINE &&
                off < rcache->off + rcache->size) {
            if (off >= rcache->off) {
                /* 是否已经存在在rcache  */
                diff = clfs_min(diff, rcache->size - (off-rcache->off));
                memcpy(data, &rcache->buffer[off-rcache->off], diff);

                data += diff;
                off += diff;
                size -= diff;
                continue;
            }

            diff = clfs_min(diff, rcache->off-off);/* rcache优先 */
        }

        rcache->block = CLFS_BLOCK_INLINE;  /* 第一种情况不能失败，存到cache  */
        rcache->off = clfs_aligndown(off, clfs->cfg->read_size);
        rcache->size = clfs_min(clfs_alignup(off+hint, clfs->cfg->read_size),
                clfs->cfg->cache_size);
        int err = clfs_dir_getslice(clfs, dir, gmask, gtag,
                rcache->off, rcache->buffer, rcache->size);/* 从读cache偏移处开始找 */
        if (err < 0) {
            return err;
        }
    }

    return 0;
}

#ifndef CLFS_READONLY
static int clfs_dir_traverse_filter(void *p,
        clfs_tag_t tag, const void *buffer) {
    clfs_tag_t *filtertag = p;
    (void)buffer;

    uint32_t mask = (tag & CLFS_MKTAG(0x100, 0, 0))
            ? CLFS_MKTAG(0x7ff, 0x3ff, 0)
            : CLFS_MKTAG(0x700, 0x3ff, 0); /* 依赖于标签结构中的唯一位的是哪个掩码 */

    if ((mask & tag) == (mask & *filtertag) ||
            clfs_tag_isdelete(*filtertag) ||
            (CLFS_MKTAG(0x7ff, 0x3ff, 0) & tag) == (
                CLFS_MKTAG(CLFS_TYPE_DELETE, 0, 0) |
                    (CLFS_MKTAG(0, 0x3ff, 0) & *filtertag))) {
        *filtertag = CLFS_MKTAG(CLFS_FROM_NOOP, 0, 0); /* 检查冗余 */
        return true;
    }

    if (clfs_tag_type1(tag) == CLFS_TYPE_SPLICE &&
            clfs_tag_id(tag) <= clfs_tag_id(*filtertag)) {
        *filtertag += CLFS_MKTAG(0, clfs_tag_splice(tag), 0);
    } /* 检查是否需要针对已创建/已删除的tags进行调整 */

    return false;
}
#endif

#ifndef CLFS_READONLY
/* clfs_dir_traverse的最大递归深度:
  遍历提交
    ->遍历
    ->遍历过滤器 */
#define CLFS_DIR_TRAVERSE_DEPTH 3

struct clfs_dir_traverse {
    const clfs_mdir_t *dir;
    clfs_off_t off;
    clfs_tag_t ptag;
    const struct clfs_mattr *attrs;
    int attrcount;

    clfs_tag_t tmask;
    clfs_tag_t ttag;
    uint16_t begin;
    uint16_t end;
    int16_t diff;

    int (*cb)(void *data, clfs_tag_t tag, const void *buffer);
    void *data;

    clfs_tag_t tag;
    const void *buffer;
    struct clfs_diskoff disk;
};

static int clfs_dir_traverse(clfs_t *clfs,
        const clfs_mdir_t *dir, clfs_off_t off, clfs_tag_t ptag,
        const struct clfs_mattr *attrs, int attrcount,
        clfs_tag_t tmask, clfs_tag_t ttag,
        uint16_t begin, uint16_t end, int16_t diff,
        int (*cb)(void *data, clfs_tag_t tag, const void *buffer), void *data) {
    /* 这个函数本身是递归的，但有界。为了允许基于工具的分析而没有不必要的代码成本，我们使用显式堆栈 */
    struct clfs_dir_traverse stack[CLFS_DIR_TRAVERSE_DEPTH-1];
    unsigned sp = 0;
    int res;

    clfs_tag_t tag;
    const void *buffer;
    struct clfs_diskoff disk;
    while (true) { /* 遍历目录和attrs */
        {
            if (off+clfs_tag_dsize(ptag) < dir->off) {
                off += clfs_tag_dsize(ptag);
                int err = clfs_bd_read(clfs,
                        NULL, &clfs->rcache, sizeof(tag),
                        dir->pair[0], off, &tag, sizeof(tag));
                if (err) {
                    return err;
                }

                tag = (clfs_frombe32(tag) ^ ptag) | 0x80000000;
                disk.block = dir->pair[0];
                disk.off = off+sizeof(clfs_tag_t);
                buffer = &disk;
                ptag = tag;
            } else if (attrcount > 0) {
                tag = attrs[0].tag;
                buffer = attrs[0].buffer;
                attrs += 1;
                attrcount -= 1;
            } else {
                res = 0; /* 完成遍历，是否从堆栈弹出 */
                break;
            }

            clfs_tag_t mask = CLFS_MKTAG(0x7ff, 0, 0);   /* 是否需要过滤 */
            if ((mask & tmask & tag) != (mask & tmask & ttag)) {
                continue;
            }

            if (clfs_tag_id(tmask) != 0) {
                CLFS_ASSERT(sp < CLFS_DIR_TRAVERSE_DEPTH);
                /* 递归，扫描重复，并根据创建/删除更新标签 */
                stack[sp] = (struct clfs_dir_traverse){
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
                cb = clfs_dir_traverse_filter;
                data = &stack[sp-1].tag;
                continue;
            }
        }

popped:
        if (clfs_tag_id(tmask) != 0 &&
                !(clfs_tag_id(tag) >= begin && clfs_tag_id(tag) < end)) { /* 是否在filter的范围内 */
            continue;
        }

        if (clfs_tag_type3(tag) == CLFS_FROM_NOOP) { /* 处理mcu端操作的特殊情况 */
            /* 什么也不做 */
        } else if (clfs_tag_type3(tag) == CLFS_FROM_MOVE) {
            /* 如果没有这个条件，clfs_dir_traverse在重命名时可能会出现代价极高的嵌套循环O(n^3)。
            发生这种情况是因为clfs_dir_traverse试图通过源目录中的标签来过滤标签，
            从而使用自己的过滤操作触发第二个clfs_dir_traverse。遍历提交，
                ->遍历过滤器
                ->遍历
                ->遍历过滤器
            然而，我们实际上并不关心过滤第二组标记，因为重复标记在过滤时没有影响。
            这个检查显式地跳过这个不必要的递归过滤，将运行时间从O(n^3)减少到O(n^2)。 */
            if (cb == clfs_dir_traverse_filter) {
                continue;
            }

            stack[sp] = (struct clfs_dir_traverse){
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
                .tag        = CLFS_MKTAG(CLFS_FROM_NOOP, 0, 0),
            };
            sp += 1;

            uint16_t fromid = clfs_tag_size(tag);
            uint16_t toid = clfs_tag_id(tag);
            dir = buffer;
            off = 0;
            ptag = 0xffffffff;
            attrs = NULL;
            attrcount = 0;
            tmask = CLFS_MKTAG(0x600, 0x3ff, 0);
            ttag = CLFS_MKTAG(CLFS_TYPE_STRUCT, 0, 0);
            begin = fromid;
            end = fromid+1;
            diff = toid-fromid+diff;
        } else if (clfs_tag_type3(tag) == CLFS_FROM_USERATTRS) {
            unsigned i;
            for (i = 0; i < clfs_tag_size(tag); i++) {
                const struct clfs_attr *a = buffer;
                res = cb(data, CLFS_MKTAG(CLFS_TYPE_USERATTR + a[i].type,
                        clfs_tag_id(tag) + diff, a[i].size), a[i].buffer);
                if (res < 0) {
                    return res;
                }

                if (res) {
                    break;
                }
            }
        } else {
            res = cb(data, tag + CLFS_MKTAG(0, diff, 0), buffer);
            if (res < 0) {
                return res;
            }

            if (res) {
                break;
            }
        }
    }

    if (sp > 0) {
        /* 从栈中弹出并返回，最好的情况是的是所有弹出都为同一个目的地  */
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

static clfs_stag_t clfs_dir_fetchmatch(clfs_t *clfs,
        clfs_mdir_t *dir, const clfs_block_t pair[2],
        clfs_tag_t fmask, clfs_tag_t ftag, uint16_t *id,
        int (*cb)(void *data, clfs_tag_t tag, const void *buffer), void *data) {
        /* 可以在获取过程中非常有效地找到标签，因为我们已经扫描了整个目录 */
    clfs_stag_t besttag = -1;

    if (pair[0] >= clfs->cfg->block_count || pair[1] >= clfs->cfg->block_count) {
        return CLFS_ERR_CORRUPT;
    } /* 如果任何一个块地址无效，我们在这里返回CLFS_ERR_CORRUPT，否则以后对该对的写入可能会失败 */

    uint32_t revs[2] = {0, 0}; /* 找到最新修改的代码块 */
    int r = 0, i;
    for (i = 0; i < 2; i++) {
        int err = clfs_bd_read(clfs,
                NULL, &clfs->rcache, sizeof(revs[i]),
                pair[i], 0, &revs[i], sizeof(revs[i]));
        revs[i] = clfs_fromle32(revs[i]);
        if (err && err != CLFS_ERR_CORRUPT) {
            return err;
        }

        if (err != CLFS_ERR_CORRUPT &&
                clfs_scmp(revs[i], revs[(i+1)%2]) > 0) {
            r = i;
        }
    }

    dir->pair[0] = pair[(r+0)%2];
    dir->pair[1] = pair[(r+1)%2];
    dir->rev = revs[(r+0)%2];
    dir->off = 0;
    /* nonzero表示发现一些commit */

    for (i = 0; i < 2; i++) {
        /* 现在扫描tags来获取实际的目录并找到可能的匹配 */
        clfs_off_t off = 0;
        clfs_tag_t ptag = 0xffffffff;

        uint16_t tempcount = 0;
        clfs_block_t temptail[2] = {CLFS_BLOCK_NULL, CLFS_BLOCK_NULL};
        bool tempsplit = false;
        clfs_stag_t tempbesttag = besttag;

        dir->rev = clfs_tole32(dir->rev);
        uint32_t crc = clfs_crc(0xffffffff, &dir->rev, sizeof(dir->rev));
        dir->rev = clfs_fromle32(dir->rev);

        while (true) {
            /* 提取下一个标签 */
            clfs_tag_t tag;
            off += clfs_tag_dsize(ptag);
            int err = clfs_bd_read(clfs,
                    NULL, &clfs->rcache, clfs->cfg->block_size,
                    dir->pair[0], off, &tag, sizeof(tag));
            if (err) {
                if (err == CLFS_ERR_CORRUPT) {
                    /* 不能继续 */
                    dir->erased = false;
                    break;
                }
                return err;
            }

            crc = clfs_crc(crc, &tag, sizeof(tag));
            tag = clfs_frombe32(tag) ^ ptag;

            /* 下一次提交尚未编程或我们不在有效范围内 */
            if (!clfs_tag_isvalid(tag)) {
                /* ???下一个commit还没有programmed完成或者不在有效的范围内 */
                dir->erased = (clfs_tag_type1(ptag) == CLFS_TYPE_CRC &&
                        dir->off % clfs->cfg->prog_size == 0);
                break;
            } else if (off + clfs_tag_dsize(tag) > clfs->cfg->block_size) {
                dir->erased = false;
                break;
            }

            ptag = tag;

            if (clfs_tag_type1(tag) == CLFS_TYPE_CRC) {
                /* 检查crc的属性 */
                uint32_t dcrc;
                err = clfs_bd_read(clfs,
                        NULL, &clfs->rcache, clfs->cfg->block_size,
                        dir->pair[0], off+sizeof(tag), &dcrc, sizeof(dcrc));
                if (err) {
                    if (err == CLFS_ERR_CORRUPT) {
                        dir->erased = false;
                        break;
                    }
                    return err;
                }
                dcrc = clfs_fromle32(dcrc);

                if (crc != dcrc) {
                    dir->erased = false;
                    break;
                }

                ptag ^= (clfs_tag_t)(clfs_tag_chunk(tag) & 1U) << 31; /* 重设下一位 */
            /* 将我们的CRC放入文件系统种子以获取伪随机数，注意我们在这里
            使用另一个CRC作为集合函数，因为它足够随机和方便 */
                clfs->seed = clfs_crc(clfs->seed, &crc, sizeof(crc));

                besttag = tempbesttag; /* 更新当前找到的 */
                dir->off = off + clfs_tag_dsize(tag);
                dir->etag = ptag;
                dir->count = tempcount;
                dir->tail[0] = temptail[0];
                dir->tail[1] = temptail[1];
                dir->split = tempsplit;

                crc = 0xffffffff; /* 重设crc  */
                continue;
            }
            /* 首先对entry进行CRC校验，希望能把它留在缓存中 */
            clfs_off_t j;
            for (j = sizeof(tag); j < clfs_tag_dsize(tag); j++) {
                uint8_t dat;
                err = clfs_bd_read(clfs,
                        NULL, &clfs->rcache, clfs->cfg->block_size,
                        dir->pair[0], off+j, &dat, 1);
                if (err) {
                    if (err == CLFS_ERR_CORRUPT) {
                        dir->erased = false;
                        break;
                    }
                    return err;
                }

                crc = clfs_crc(crc, &dat, 1);
            }

            if (clfs_tag_type1(tag) == CLFS_TYPE_NAME) {
                /* 是否为目录修改标签 */
                if (clfs_tag_id(tag) >= tempcount) {
                    /* 如果需要的话增加文件的数量 */
                    tempcount = clfs_tag_id(tag) + 1;
                }
            } else if (clfs_tag_type1(tag) == CLFS_TYPE_SPLICE) {
                tempcount += clfs_tag_splice(tag);

                if (tag == (CLFS_MKTAG(CLFS_TYPE_DELETE, 0, 0) |
                        (CLFS_MKTAG(0, 0x3ff, 0) & tempbesttag))) {
                    tempbesttag |= 0x80000000;
                } else if (tempbesttag != -1 &&
                        clfs_tag_id(tag) <= clfs_tag_id(tempbesttag)) {
                    tempbesttag += CLFS_MKTAG(0, clfs_tag_splice(tag), 0);
                }
            } else if (clfs_tag_type1(tag) == CLFS_TYPE_TAIL) {
                tempsplit = (clfs_tag_chunk(tag) & 1);

                err = clfs_bd_read(clfs,
                        NULL, &clfs->rcache, clfs->cfg->block_size,
                        dir->pair[0], off+sizeof(tag), &temptail, 8);
                if (err) {
                    if (err == CLFS_ERR_CORRUPT) {
                        dir->erased = false;
                        break;
                    }
                }
                clfs_pair_fromle32(temptail);
            }

            if ((fmask & tag) == (fmask & ftag)) {
                /* ???如果为fetcher找到匹配 */
                int res = cb(data, tag, &(struct clfs_diskoff){
                        dir->pair[0], off+sizeof(tag)});
                if (res < 0) {
                    if (res == CLFS_ERR_CORRUPT) {
                        dir->erased = false;
                        break;
                    }
                    return res;
                }

                if (res == CLFS_CMP_EQ) {
                    /* 找到匹配 */
                    tempbesttag = tag;
                } else if ((CLFS_MKTAG(0x7ff, 0x3ff, 0) & tag) ==
                        (CLFS_MKTAG(0x7ff, 0x3ff, 0) & tempbesttag)) {
                /* 发现了一个相同的标签，但内容不匹配，这一定意味着我们最好的标签被覆盖了 */
                    tempbesttag = -1;
                } else if (res == CLFS_CMP_GT &&
                        clfs_tag_id(tag) <= clfs_tag_id(tempbesttag)) {
                            /* 找到了更好的匹配，跟踪记录并排序 */
                    tempbesttag = tag | 0x80000000;
                }
            }
        }

        /*********************************************************************************************************
        认为我们现在有的足够好
        *********************************************************************************************************/
        if (dir->off > 0) {
            /* 合成移动 */
            if (clfs_gstate_hasmovehere(&clfs->gdisk, dir->pair)) {
                if (clfs_tag_id(clfs->gdisk.tag) == clfs_tag_id(besttag)) {
                    besttag |= 0x80000000;
                } else if (besttag != -1 &&
                        clfs_tag_id(clfs->gdisk.tag) < clfs_tag_id(besttag)) {
                    besttag -= CLFS_MKTAG(0, 1, 0);
                }
            }

            if (id) {
                /* 找到tag 或者找到最好的id */
                *id = clfs_min(clfs_tag_id(besttag), dir->count);
            }

            if (clfs_tag_isvalid(besttag)) {
                return besttag;
            } else if (clfs_tag_id(besttag) < dir->count) {
                return CLFS_ERR_NOENT;
            } else {
                return 0;
            }
        }

        clfs_pair_swap(dir->pair);
        /* 没找到，尝试其他块 */
        dir->rev = revs[(r+1)%2];
    }

    CLFS_ERROR("Corrupted dir pair at {0x%"PRIx32", 0x%"PRIx32"}",
            dir->pair[0], dir->pair[1]);
    return CLFS_ERR_CORRUPT;
}

static int clfs_dir_fetch(clfs_t *clfs,
        clfs_mdir_t *dir, const clfs_block_t pair[2]) {
        /* 注意，mask=-1, tag=-1永远不能匹配标签，因为这个模式设置了无效的位 */
    return (int)clfs_dir_fetchmatch(clfs, dir, pair,
            (clfs_tag_t)-1, (clfs_tag_t)-1, NULL, NULL, NULL);
}

static int clfs_dir_getgstate(clfs_t *clfs, const clfs_mdir_t *dir,
        clfs_gstate_t *gstate) {
    clfs_gstate_t temp;
    clfs_stag_t res = clfs_dir_get(clfs, dir, CLFS_MKTAG(0x7ff, 0, 0),
            CLFS_MKTAG(CLFS_TYPE_MOVESTATE, 0, sizeof(temp)), &temp);
    if (res < 0 && res != CLFS_ERR_NOENT) {
        return res;
    }

    if (res != CLFS_ERR_NOENT) {
        /* 异或一起找到结果的gstate */
        clfs_gstate_fromle32(&temp);
        clfs_gstate_xor(gstate, &temp);
    }

    return 0;
}

static int clfs_dir_getinfo(clfs_t *clfs, clfs_mdir_t *dir,
        uint16_t id, struct clfs_info *info) {
    if (id == 0x3ff) { /* 对根的特别情况 */
        strcpy(info->name, "/");
        info->type = CLFS_TYPE_DIR;
        return 0;
    }

    clfs_stag_t tag = clfs_dir_get(clfs, dir, CLFS_MKTAG(0x780, 0x3ff, 0),
            CLFS_MKTAG(CLFS_TYPE_NAME, id, clfs->name_max+1), info->name);
    if (tag < 0) {
        return (int)tag;
    }

    info->type = clfs_tag_type3(tag);

    struct clfs_ctz ctz;
    tag = clfs_dir_get(clfs, dir, CLFS_MKTAG(0x700, 0x3ff, 0),
            CLFS_MKTAG(CLFS_TYPE_STRUCT, id, sizeof(ctz)), &ctz);
    if (tag < 0) {
        return (int)tag;
    }
    clfs_ctz_fromle32(&ctz);

    if (clfs_tag_type3(tag) == CLFS_TYPE_CTZSTRUCT) {
        info->size = ctz.size;
    } else if (clfs_tag_type3(tag) == CLFS_TYPE_INLINESTRUCT) {
        info->size = clfs_tag_size(tag);
    }

    return 0;
}

struct clfs_dir_find_match {
    clfs_t *clfs;
    const void *name;
    clfs_size_t size;
};

static int clfs_dir_find_match(void *data,
        clfs_tag_t tag, const void *buffer) {
    struct clfs_dir_find_match *name = data;
    clfs_t *clfs = name->clfs;
    const struct clfs_diskoff *disk = buffer;

    clfs_size_t diff = clfs_min(name->size, clfs_tag_size(tag));
    int res = clfs_bd_cmp(clfs,
            /* 与磁盘交互 */
            NULL, &clfs->rcache, diff,
            disk->block, disk->off, name->name, diff);
    if (res != CLFS_CMP_EQ) {
        return res;
    }

    if (name->size != clfs_tag_size(tag)) { /* 只有大小不变时才相等 */
        return (name->size < clfs_tag_size(tag)) ? CLFS_CMP_LT : CLFS_CMP_GT;
    }

    /* 找到一个匹配! */
    return CLFS_CMP_EQ;
}

static clfs_stag_t clfs_dir_find(clfs_t *clfs, clfs_mdir_t *dir,
        const char **path, uint16_t *id) {

    const char *name = *path;
    /*如果可以找到路径，则将其简化为单个名称 */
    if (id) {
        *id = 0x3ff;
    }

    clfs_stag_t tag = CLFS_MKTAG(CLFS_TYPE_DIR, 0x3ff, 0);
    /*  默认为root dir   */
    dir->tail[0] = clfs->root[0];
    dir->tail[1] = clfs->root[1];

    while (true) {
nextname:

        name += strspn(name, "/");
        /*  跳过斜杠   */
        clfs_size_t namelen = strcspn(name, "/");

        if ((namelen == 1 && memcmp(name, ".", 1) == 0) ||
        /*  跳过的'.'和root '..'   */
            (namelen == 2 && memcmp(name, "..", 2) == 0)) {
            name += namelen;
            goto nextname;
        }

        const char *suffix = name + namelen;
        /*  跳过匹配'..的名字   */
        clfs_size_t sufflen;
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

        if (name[0] == '\0') {
            /*   发现途径  */
            return tag;
        }

        *path = name;
        /*  更新我们目前的发现   */

        if (clfs_tag_type3(tag) != CLFS_TYPE_DIR) {
            /*  只有当我们到达一个目录时才会继续   */
            return CLFS_ERR_NOTDIR;
        }

        if (clfs_tag_id(tag) != 0x3ff) {
            /*   获取入口数据  */
            clfs_stag_t res = clfs_dir_get(clfs, dir, CLFS_MKTAG(0x700, 0x3ff, 0),
                    CLFS_MKTAG(CLFS_TYPE_STRUCT, clfs_tag_id(tag), 8), dir->tail);
            if (res < 0) {
                return res;
            }
            clfs_pair_fromle32(dir->tail);
        }

        while (true) {
            /*  查找与名称匹配的条目   */
            tag = clfs_dir_fetchmatch(clfs, dir, dir->tail,
                    CLFS_MKTAG(0x780, 0, 0),
                    CLFS_MKTAG(CLFS_TYPE_NAME, 0, namelen),
                    (strchr(name, '/') == NULL) ? id : NULL,
                    /*  是否是最后要给名称   */
                    clfs_dir_find_match, &(struct clfs_dir_find_match){
                        clfs, name, namelen});
            if (tag < 0) {
                return tag;
            }

            if (tag) {
                break;
            }

            if (!dir->split) {
                return CLFS_ERR_NOENT;
            }
        }

        name += namelen;
        /*  到下一个名称   */
    }
}

/*********************************************************************************************************
  结构体clfs_commit
*********************************************************************************************************/
struct clfs_commit {
    clfs_block_t block;
    clfs_off_t off;
    clfs_tag_t ptag;
    uint32_t crc;

    clfs_off_t begin;
    clfs_off_t end;
};

#ifndef CLFS_READONLY/*提交内容正式写入设备7*/
static int clfs_dir_commitprog(clfs_t *clfs, struct clfs_commit *commit,
        const void *buffer, clfs_size_t size) {
    int err = clfs_bd_prog(clfs,
            &clfs->pcache, &clfs->rcache, false,
            commit->block, commit->off ,
            (const uint8_t*)buffer, size);
    if (err) {
        return err;
    }

    commit->crc = clfs_crc(commit->crc, buffer, size);
    commit->off += size;
    return 0;
}
#endif

#ifndef CLFS_READONLY
static int clfs_dir_commitattr(clfs_t *clfs, struct clfs_commit *commit,
        clfs_tag_t tag, const void *buffer) {

    clfs_size_t dsize = clfs_tag_dsize(tag);
    /*  检查是否合适   */
    if (commit->off + dsize > commit->end) {
        return CLFS_ERR_NOSPC;
    }

    clfs_tag_t ntag = clfs_tobe32((tag & 0x7fffffff) ^ commit->ptag);
    /*   写标签  */
    int err = clfs_dir_commitprog(clfs, commit, &ntag, sizeof(ntag));
    if (err) {
        return err;
    }

    if (!(tag & 0x80000000)) {
        err = clfs_dir_commitprog(clfs, commit, buffer, dsize-sizeof(tag));
        /*  从内存   */
        if (err) {
            return err;
        }
    } else {

        const struct clfs_diskoff *disk = buffer;
        /*  从硬盘   */
        clfs_off_t i;
        for (i = 0; i < dsize-sizeof(tag); i++) {

            uint8_t dat;
            err = clfs_bd_read(clfs,
                    NULL, &clfs->rcache, dsize-sizeof(tag)-i,
                    /*  依赖缓存来提高效率   */
                    disk->block, disk->off+i, &dat, 1);
            if (err) {
                return err;
            }

            err = clfs_dir_commitprog(clfs, commit, &dat, 1);
            if (err) {
                return err;
            }
        }
    }

    commit->ptag = tag & 0x7fffffff;
    return 0;
}
#endif

#ifndef CLFS_READONLY
static int clfs_dir_commitcrc(clfs_t *clfs, struct clfs_commit *commit) {

    const clfs_off_t end = clfs_alignup(commit->off + 2*sizeof(uint32_t),
    /*  对齐到程序单元   */
            clfs->cfg->prog_size);

    clfs_off_t off1 = 0;
    uint32_t crc1 = 0;

    /*  创建CRC标签来填充提交的剩余部分，注意填充是不crced的，这让读取跳过填充，但使提交有点复杂  */
    while (commit->off < end) {
        clfs_off_t off = commit->off + sizeof(clfs_tag_t);
        clfs_off_t noff = clfs_min(end - off, 0x3fe) + off;
        if (noff < end) {
            noff = clfs_min(noff, end - 2*sizeof(uint32_t));
        }


        clfs_tag_t tag = 0xffffffff;
        /*  从下一个程序单元读取擦除状态   */
        int err = clfs_bd_read(clfs,
                NULL, &clfs->rcache, sizeof(tag),
                commit->block, noff, &tag, sizeof(tag));
        if (err && err != CLFS_ERR_CORRUPT) {
            return err;
        }


        bool reset = ~clfs_frombe32(tag) >> 31;
        /*   建立CRC标签  */
        tag = CLFS_MKTAG(CLFS_TYPE_CRC + reset, 0x3ff, noff - off);


        uint32_t footer[2];
        footer[0] = clfs_tobe32(tag ^ commit->ptag);
        commit->crc = clfs_crc(commit->crc, &footer[0], sizeof(footer[0]));
        /*  写入CRC   */
        footer[1] = clfs_tole32(commit->crc);
        err = clfs_bd_prog(clfs,
                &clfs->pcache, &clfs->rcache, false,
                commit->block, commit->off, &footer, sizeof(footer));
        if (err) {
            return err;
        }


        if (off1 == 0) {
            off1 = commit->off + sizeof(uint32_t);
            /*  跟踪非填充校验和以进行验证   */
            crc1 = commit->crc;
        }

        commit->off += sizeof(tag)+clfs_tag_size(tag);
        commit->ptag = tag ^ ((clfs_tag_t)reset << 31);
        commit->crc = 0xffffffff;
        /*  重设CRC为下一个"commit"   */
    }


    int err = clfs_bd_sync(clfs, &clfs->pcache, &clfs->rcache, false);
    /*  刷新缓冲区   */
    if (err) {
        return err;
    }


    clfs_off_t off = commit->begin;
    /*  成功提交，检查checksum以确保   */
    clfs_off_t noff = off1;
    while (off < end) {
        uint32_t crc = 0xffffffff;
        clfs_off_t i;
        for (i = off; i < noff+sizeof(uint32_t); i++) {
            /* 检查写入的crc，可以捕获变为只读并与提交大小完全匹配的块 */
            if (i == off1 && crc != crc1) {
                return CLFS_ERR_CORRUPT;
            }


            uint8_t dat;
            err = clfs_bd_read(clfs,   /*   让缓存来提高效率  */
                    NULL, &clfs->rcache, noff+sizeof(uint32_t)-i,
                    commit->block, i, &dat, 1);
            if (err) {
                return err;
            }

            crc = clfs_crc(crc, &dat, 1);
        }


        if (crc != 0) {
            return CLFS_ERR_CORRUPT;
            /*  检测到写错误   */
        }


        off = clfs_min(end - noff, 0x3fe) + noff;
        /*  跳过填充   */
        if (off < end) {
            off = clfs_min(off, end - 2*sizeof(uint32_t));
        }
        noff = off + sizeof(uint32_t);
    }

    return 0;
}
#endif

#ifndef CLFS_READONLY
static int clfs_dir_alloc(clfs_t *clfs, clfs_mdir_t *dir) {

    int i;
    for (i = 0; i < 2; i++) {
        int err = clfs_alloc(clfs, &dir->pair[(i+1)%2]);
        /* 分配一对dir块(向后，所以我们先写第1块）*/
        if (err) {
            return err;
        }
    }

    dir->rev = 0;
    /* 初始化修订计数为0 */
    int err = clfs_bd_read(clfs,
    /* 假装修改可能是有效的，并读出 */
            NULL, &clfs->rcache, sizeof(dir->rev),
            dir->pair[0], 0, &dir->rev, sizeof(dir->rev));
    dir->rev = clfs_fromle32(dir->rev);
    if (err && err != CLFS_ERR_CORRUPT) {
        return err;
    }

    /* 为了确保不会立即退出，将新的修订计数与block_cycles对齐 */
    if (clfs->cfg->block_cycles > 0) {
        dir->rev = clfs_alignup(dir->rev, ((clfs->cfg->block_cycles+1)|1));
    }

    dir->off = sizeof(dir->rev);
    /* 设置默认值  */
    dir->etag = 0xffffffff;
    dir->count = 0;
    dir->tail[0] = CLFS_BLOCK_NULL;
    dir->tail[1] = CLFS_BLOCK_NULL;
    dir->erased = false;
    dir->split = false;

    /* 待处理  */
    return 0;
}
#endif

#ifndef CLFS_READONLY
static int clfs_dir_drop(clfs_t *clfs, clfs_mdir_t *dir, clfs_mdir_t *tail) {

    int err = clfs_dir_getgstate(clfs, tail, &clfs->gdelta);
    /*  三态控制   */
    if (err) {
        return err;
    }


    clfs_pair_tole32(tail->tail);
    err = clfs_dir_commit(clfs, dir, CLFS_MKATTRS(
            {CLFS_MKTAG(CLFS_TYPE_TAIL + tail->split, 0x3ff, 8), tail->tail}));
    clfs_pair_fromle32(tail->tail);
    if (err) {
        return err;
    }

    return 0;
}
#endif

#ifndef CLFS_READONLY
static int clfs_dir_split(clfs_t *clfs,
        clfs_mdir_t *dir, const struct clfs_mattr *attrs, int attrcount,
        clfs_mdir_t *source, uint16_t split, uint16_t end) {

    clfs_mdir_t tail;
    int err = clfs_dir_alloc(clfs, &tail);
    /*  创建尾部元数据对   */
    if (err) {
        return err;
    }

    tail.split = dir->split;
    tail.tail[0] = dir->tail[0];
    tail.tail[1] = dir->tail[1];


    int res = clfs_dir_compact(clfs, &tail, attrs, attrcount, source, split, end);
    /*  这里不关心clfs_ok_relocation   */
    if (res < 0) {
        return res;
    }

    dir->tail[0] = tail.pair[0];
    dir->tail[1] = tail.pair[1];
    dir->split = true;


    if (clfs_pair_cmp(dir->pair, clfs->root) == 0 && split == 0) {
        /*  如果需要，更新根目录   */
        clfs->root[0] = tail.pair[0];
        clfs->root[1] = tail.pair[1];
    }

    return 0;
}
#endif

#ifndef CLFS_READONLY
static int clfs_dir_commit_size(void *p, clfs_tag_t tag, const void *buffer) {
    clfs_size_t *size = p;
    (void)buffer;

    *size += clfs_tag_dsize(tag);
    return 0;
}
#endif

#ifndef CLFS_READONLY
struct clfs_dir_commit_commit {
    clfs_t *clfs;
    struct clfs_commit *commit;
};
#endif

#ifndef CLFS_READONLY
static int clfs_dir_commit_commit(void *p, clfs_tag_t tag, const void *buffer) {
    struct clfs_dir_commit_commit *commit = p;
    return clfs_dir_commitattr(commit->clfs, commit->commit, tag, buffer);
}
#endif

#ifndef CLFS_READONLY
static bool clfs_dir_needsrelocation(clfs_t *clfs, clfs_mdir_t *dir) {
    /* 如果修订计数rev == n * block_cycles，应该强制重定位，
     * 实际上使用了(block_cycles+1)|1  */
    return (clfs->cfg->block_cycles > 0
            && ((dir->rev + 1) % ((clfs->cfg->block_cycles+1)|1) == 0));
}
#endif

#ifndef CLFS_READONLY
static int clfs_dir_compact(clfs_t *clfs,
        clfs_mdir_t *dir, const struct clfs_mattr *attrs, int attrcount,
        clfs_mdir_t *source, uint16_t begin, uint16_t end) {

    bool relocated = false;
    bool tired = clfs_dir_needsrelocation(clfs, dir);
    /*  保存一些状态在case块是坏的   */


    dir->rev += 1;
    /*  增量修订计数   */

    /*  不要在迁移过程中主动重新定位块，这可能会导致许多失败状态   */
#ifdef CLFS_MIGRATE
    if (clfs->clfs1) {
        tired = false;
    }
#endif

    if (tired && clfs_pair_cmp(dir->pair, (const clfs_block_t[2]){0, 1}) != 0) {
        goto relocate;
    }

    /*  开始循环提交压缩到块   */
    while (true) {
        {

            struct clfs_commit commit = {
                /*  设置提交状态   */
                .block = dir->pair[1],
                .off = 0,
                .ptag = 0xffffffff,
                .crc = 0xffffffff,

                .begin = 0,
                .end = (clfs->cfg->metadata_max ?
                    clfs->cfg->metadata_max : clfs->cfg->block_size) - 8,
            };


            int err = clfs_bd_erase(clfs, dir->pair[1]);
            /*  擦除要写入的块   */
            if (err) {
                if (err == CLFS_ERR_CORRUPT) {
                    goto relocate;
                }
                return err;
            }


            dir->rev = clfs_tole32(dir->rev);
            /*  在块的首部写入rev（修订计数）   */
            err = clfs_dir_commitprog(clfs, &commit,
                    &dir->rev, sizeof(dir->rev));
            dir->rev = clfs_fromle32(dir->rev);
            if (err) {
                if (err == CLFS_ERR_CORRUPT) {
                    goto relocate;
                }
                return err;
            }


            err = clfs_dir_traverse(clfs,
            /*  遍历目录，这次写出所有唯一的标签   */
                    source, 0, 0xffffffff, attrs, attrcount,
                    CLFS_MKTAG(0x400, 0x3ff, 0),
                    CLFS_MKTAG(CLFS_TYPE_NAME, 0, 0),
                    begin, end, -begin,
                    clfs_dir_commit_commit, &(struct clfs_dir_commit_commit){
                        clfs, &commit});
            if (err) {
                if (err == CLFS_ERR_CORRUPT) {
                    goto relocate;
                }
                return err;
            }


            if (!clfs_pair_isnull(dir->tail)) {
                /*  提交尾部，最后一次大小检查   */
                clfs_pair_tole32(dir->tail);
                err = clfs_dir_commitattr(clfs, &commit,
                        CLFS_MKTAG(CLFS_TYPE_TAIL + dir->split, 0x3ff, 8),
                        dir->tail);
                clfs_pair_fromle32(dir->tail);
                if (err) {
                    if (err == CLFS_ERR_CORRUPT) {
                        goto relocate;
                    }
                    return err;
                }
            }


            clfs_gstate_t delta = {0};
            /* 带gstate   */
            if (!relocated) {
                clfs_gstate_xor(&delta, &clfs->gdisk);
                clfs_gstate_xor(&delta, &clfs->gstate);
            }
            clfs_gstate_xor(&delta, &clfs->gdelta);
            delta.tag &= ~CLFS_MKTAG(0, 0, 0x3ff);

            err = clfs_dir_getgstate(clfs, dir, &delta);
            if (err) {
                return err;
            }

            if (!clfs_gstate_iszero(&delta)) {
                clfs_gstate_tole32(&delta);
                err = clfs_dir_commitattr(clfs, &commit,
                        CLFS_MKTAG(CLFS_TYPE_MOVESTATE, 0x3ff,
                            sizeof(delta)), &delta);
                if (err) {
                    if (err == CLFS_ERR_CORRUPT) {
                        goto relocate;
                    }
                    return err;
                }
            }


            err = clfs_dir_commitcrc(clfs, &commit);
            /*  使用CRC完成提交   */
            if (err) {
                if (err == CLFS_ERR_CORRUPT) {
                    goto relocate;
                }
                return err;
            }


            CLFS_ASSERT(commit.off % clfs->cfg->prog_size == 0);
            /*  成功的压缩，交换dir对指示最近  */
            clfs_pair_swap(dir->pair);
            dir->count = end - begin;
            dir->off = commit.off;
            dir->etag = commit.ptag;

            clfs->gdelta = (clfs_gstate_t){0};
            /*   更新gstate  */
            if (!relocated) {
                clfs->gdisk = clfs->gstate;
            }
        }
        break;

relocate:

        relocated = true;
        /*  提交已损坏，删除缓存并准备重新定位块   */
        clfs_cache_drop(clfs, &clfs->pcache);
        if (!tired) {
            CLFS_DEBUG("Bad block at 0x%"PRIx32, dir->pair[1]);
        }


        if (clfs_pair_cmp(dir->pair, (const clfs_block_t[2]){0, 1}) == 0) {
            /*  不能重新定位超级块，文件系统现在冻结   */
            CLFS_WARN("Superblock 0x%"PRIx32" has become unwritable",
                    dir->pair[1]);
            return CLFS_ERR_NOSPC;
        }


        int err = clfs_alloc(clfs, &dir->pair[1]);
        /*  重置一半的pair   */
        if (err && (err != CLFS_ERR_NOSPC || !tired)) {
            return err;
        }

        tired = false;
        continue;
    }

    return relocated ? CLFS_OK_RELOCATED : 0;
}
#endif

#ifndef CLFS_READONLY /*检查是否需要拆分元数据对的提交，begin/end标识在链表中的位置*/
static int clfs_dir_splittingcompact(clfs_t *clfs, clfs_mdir_t *dir,
        const struct clfs_mattr *attrs, int attrcount,
        clfs_mdir_t *source, uint16_t begin, uint16_t end) {
    while (true) {
        /*  找到第一次拆分的大小，我们通过减半拆分来实现，直到保证元数据能够匹配为止   */
        clfs_size_t split = begin;
        while (end - split > 1) {
            clfs_size_t size = 0;
            int err = clfs_dir_traverse(clfs,
                    source, 0, 0xffffffff, attrs, attrcount,
                    CLFS_MKTAG(0x400, 0x3ff, 0),
                    CLFS_MKTAG(CLFS_TYPE_NAME, 0, 0),
                    split, end, -split,
                    clfs_dir_commit_size, &size);
            if (err) {
                return err;
            }


            if (end - split < 0xff
                    && size <= clfs_min(clfs->cfg->block_size - 36,
                        clfs_alignup(
                            (clfs->cfg->metadata_max
                                ? clfs->cfg->metadata_max
                                : clfs->cfg->block_size)/2,
                            clfs->cfg->prog_size))) {
                break;
            }

            split = split + ((end - split) / 2);
        }

        if (split == begin) {
            /*  不需要分割   */
            break;
        }

        int err = clfs_dir_split(clfs, dir, attrs, attrcount,
        /*  分裂成两个元数据对并继续   */
                source, split, end);
        if (err && err != CLFS_ERR_NOSPC) {
            return err;
        }

        if (err) {
             /*  不能分配一个新的块，尝试压缩性能下降   */
            CLFS_WARN("Unable to split {0x%"PRIx32", 0x%"PRIx32"}",
                    dir->pair[0], dir->pair[1]);
            break;
        } else {
            end = split;
        }
    }

    if (clfs_dir_needsrelocation(clfs, dir)
            && clfs_pair_cmp(dir->pair, (const clfs_block_t[2]){0, 1}) == 0) {

        clfs_ssize_t size = clfs_fs_rawsize(clfs);
        /*  写入超块太多   */
        if (size < 0) {
            return size;
        }


        if ((clfs_size_t)size < clfs->cfg->block_count/2) {
            /*  谨慎扩张   */
            CLFS_DEBUG("Expanding superblock at rev %"PRIu32, dir->rev);
            int err = clfs_dir_split(clfs, dir, attrs, attrcount,
                    source, begin, end);
            if (err && err != CLFS_ERR_NOSPC) {
                return err;
            }

            if (err) {
                CLFS_WARN("Unable to expand superblock");
            } else {
                end = begin;
            }
        }
    }

    return clfs_dir_compact(clfs, dir, attrs, attrcount, source, begin, end);
}
#endif

#ifndef CLFS_READONLY /* 不考虑孤儿节点的提交 */
static int clfs_dir_relocatingcommit(clfs_t *clfs, clfs_mdir_t *dir,
        const clfs_block_t pair[2],
        const struct clfs_mattr *attrs, int attrcount,
        clfs_mdir_t *pdir) {
    int state = 0;

    bool hasdelete = false;
    /*  计算更改目录   */
    int i;
    for (i = 0; i < attrcount; i++) {
        if (clfs_tag_type3(attrs[i].tag) == CLFS_TYPE_CREATE) {
            dir->count += 1;  /*节点数目自增*/
        } else if (clfs_tag_type3(attrs[i].tag) == CLFS_TYPE_DELETE) {
            CLFS_ASSERT(dir->count > 0);
            dir->count -= 1;  /*节点数目自减*/
            hasdelete = true;
        } else if (clfs_tag_type1(attrs[i].tag) == CLFS_TYPE_TAIL) {/*跟新tail*/
            dir->tail[0] = ((clfs_block_t*)attrs[i].buffer)[0];
            dir->tail[1] = ((clfs_block_t*)attrs[i].buffer)[1];
            dir->split = (clfs_tag_chunk(attrs[i].tag) & 1);
            clfs_pair_fromle32(dir->tail);
        }
    }

    if (hasdelete && dir->count == 0) {
        /*   是否应该删除目录块   */
        CLFS_ASSERT(pdir);
        int err = clfs_fs_pred(clfs, dir->pair, pdir);
        if (err && err != CLFS_ERR_NOENT) {
            return err;
        }

        if (err != CLFS_ERR_NOENT && pdir->split) {
            state = CLFS_OK_DROPPED;
            goto fixmlist;
        }
    }

    if (dir->erased) {
        struct clfs_commit commit = {
            /*  尝试提交   */
            .block = dir->pair[0],
            .off = dir->off,
            .ptag = dir->etag,
            .crc = 0xffffffff,

            .begin = dir->off,
            .end = (clfs->cfg->metadata_max ?
                clfs->cfg->metadata_max : clfs->cfg->block_size) - 8,
        };

        clfs_pair_tole32(dir->tail);
        /*  遍历需要写出来的属性   */
        int err = clfs_dir_traverse(clfs,
                dir, dir->off, dir->etag, attrs, attrcount,
                0, 0, 0, 0, 0,
                clfs_dir_commit_commit, &(struct clfs_dir_commit_commit){
                    clfs, &commit});
        clfs_pair_fromle32(dir->tail);
        if (err) {
            if (err == CLFS_ERR_NOSPC || err == CLFS_ERR_CORRUPT) {
                goto compact;
            }
            return err;
        }

        clfs_gstate_t delta = {0};
        /* 提交任何全局差异  */
        clfs_gstate_xor(&delta, &clfs->gstate);
        clfs_gstate_xor(&delta, &clfs->gdisk);
        clfs_gstate_xor(&delta, &clfs->gdelta);
        delta.tag &= ~CLFS_MKTAG(0, 0, 0x3ff);
        if (!clfs_gstate_iszero(&delta)) {
            err = clfs_dir_getgstate(clfs, dir, &delta);
            if (err) {
                return err;
            }

            clfs_gstate_tole32(&delta);
            err = clfs_dir_commitattr(clfs, &commit,
                    CLFS_MKTAG(CLFS_TYPE_MOVESTATE, 0x3ff,
                        sizeof(delta)), &delta);
            if (err) {
                if (err == CLFS_ERR_NOSPC || err == CLFS_ERR_CORRUPT) {
                    goto compact;
                }
                return err;
            }
        }

        err = clfs_dir_commitcrc(clfs, &commit);
        /*   完成CRC的提交  */
        if (err) {
            if (err == CLFS_ERR_NOSPC || err == CLFS_ERR_CORRUPT) {
                goto compact;
            }
            return err;
        }

        CLFS_ASSERT(commit.off % clfs->cfg->prog_size == 0);
        /*  成功提交，更新dir，更新gstate   */
        dir->off = commit.off;
        dir->etag = commit.ptag;
        clfs->gdisk = clfs->gstate;
        clfs->gdelta = (clfs_gstate_t){0};

        goto fixmlist;
    }

compact:
    clfs_cache_drop(clfs, &clfs->pcache);
    /*  返回压缩   */

    state = clfs_dir_splittingcompact(clfs, dir, attrs, attrcount,
            dir, 0, dir->count);
    if (state < 0) {
        return state;
    }

    goto fixmlist;

fixmlist:;
    clfs_block_t oldpair[2] = {pair[0], pair[1]};
    struct clfs_mlist *d;
    for (d = clfs->mlist; d; d = d->next) {
        if (clfs_pair_cmp(d->m.pair, oldpair) == 0) {
            d->m = *dir;
            if (d->m.pair != pair) {
                int i;
                for (i = 0; i < attrcount; i++) {
                    if (clfs_tag_type3(attrs[i].tag) == CLFS_TYPE_DELETE &&
                            d->id == clfs_tag_id(attrs[i].tag)) {
                        d->m.pair[0] = CLFS_BLOCK_NULL;
                        d->m.pair[1] = CLFS_BLOCK_NULL;
                    } else if (clfs_tag_type3(attrs[i].tag) == CLFS_TYPE_DELETE &&
                            d->id > clfs_tag_id(attrs[i].tag)) {
                        d->id -= 1;
                        if (d->type == CLFS_TYPE_DIR) {
                            ((clfs_dir_t*)d)->pos -= 1;
                        }
                    } else if (clfs_tag_type3(attrs[i].tag) == CLFS_TYPE_CREATE &&
                            d->id >= clfs_tag_id(attrs[i].tag)) {
                        d->id += 1;
                        if (d->type == CLFS_TYPE_DIR) {
                            ((clfs_dir_t*)d)->pos += 1;
                        }
                    }
                }
            }

            while (d->id >= d->m.count && d->m.split) {
                d->id -= d->m.count;
                int err = clfs_dir_fetch(clfs, &d->m, d->m.tail);
                if (err) {
                    return err;
                }
            }
        }
    }

    return state;
}
#endif

#ifndef CLFS_READONLY /* 返回孤儿节点的目录数据条目提交 */
static int clfs_dir_orphaningcommit(clfs_t *clfs, clfs_mdir_t *dir,
        const struct clfs_mattr *attrs, int attrcount) {
    clfs_file_t *f;
    for (f = (clfs_file_t*)clfs->mlist; f; f = f->next) {
        if (dir != &f->m && clfs_pair_cmp(f->m.pair, dir->pair) == 0 &&
                f->type == CLFS_TYPE_REG && (f->flags & CLFS_F_INLINE) &&
                f->ctz.size > clfs->cfg->cache_size) {
            int err = clfs_file_outline(clfs, f);
            if (err) {
                return err;
            }

            err = clfs_file_flush(clfs, f);
            if (err) {
                return err;
            }
        }
    }

    clfs_block_t lpair[2] = {dir->pair[0], dir->pair[1]};
    clfs_mdir_t ldir = *dir;   /* 元数据对的副本 */
    clfs_mdir_t pdir;
    int state = clfs_dir_relocatingcommit(clfs, &ldir, dir->pair,
            attrs, attrcount, &pdir);
    if (state < 0) {
        return state;
    }

    if (clfs_pair_cmp(dir->pair, lpair) == 0) {
        *dir = ldir;
    }


    if (state == CLFS_OK_DROPPED) {
        /*  需要删除   */
        // steal state
        int err = clfs_dir_getgstate(clfs, dir, &clfs->gdelta);
        if (err) {
            return err;
        }

        lpair[0] = pdir.pair[0];
        /*  不能创建递归删除   */
        lpair[1] = pdir.pair[1];
        clfs_pair_tole32(dir->tail);
        state = clfs_dir_relocatingcommit(clfs, &pdir, lpair, CLFS_MKATTRS(
                    {CLFS_MKTAG(CLFS_TYPE_TAIL + dir->split, 0x3ff, 8),
                        dir->tail}),
                NULL);
        clfs_pair_fromle32(dir->tail);
        if (state < 0) {
            return state;
        }

        ldir = pdir;
    }

    bool orphans = false;
    while (state == CLFS_OK_RELOCATED) {
        /* 需要重新定位    */
        CLFS_DEBUG("Relocating {0x%"PRIx32", 0x%"PRIx32"} "
                    "-> {0x%"PRIx32", 0x%"PRIx32"}",
                lpair[0], lpair[1], ldir.pair[0], ldir.pair[1]);
        state = 0;

        if (clfs_pair_cmp(lpair, clfs->root) == 0) {
            /*  更新内部根目录   */
            clfs->root[0] = ldir.pair[0];
            clfs->root[1] = ldir.pair[1];
        }

        struct clfs_mlist *d;
        for (d = clfs->mlist; d; d = d->next) {
            /*  更新内部跟踪的dirs   */
            if (clfs_pair_cmp(lpair, d->m.pair) == 0) {
                d->m.pair[0] = ldir.pair[0];
                d->m.pair[1] = ldir.pair[1];
            }

            if (d->type == CLFS_TYPE_DIR &&
                    clfs_pair_cmp(lpair, ((clfs_dir_t*)d)->head) == 0) {
                ((clfs_dir_t*)d)->head[0] = ldir.pair[0];
                ((clfs_dir_t*)d)->head[1] = ldir.pair[1];
            }
        }

        clfs_stag_t tag = clfs_fs_parent(clfs, lpair, &pdir);
        /*  找到父节点   */
        if (tag < 0 && tag != CLFS_ERR_NOENT) {
            return tag;
        }

        bool hasparent = (tag != CLFS_ERR_NOENT);
        if (tag != CLFS_ERR_NOENT) {
            int err = clfs_fs_preporphans(clfs, +1);
            if (err) {
                return err;
            }

            uint16_t moveid = 0x3ff;
            if (clfs_gstate_hasmovehere(&clfs->gstate, pdir.pair)) {
                moveid = clfs_tag_id(clfs->gstate.tag);
                CLFS_DEBUG("Fixing move while relocating "
                        "{0x%"PRIx32", 0x%"PRIx32"} 0x%"PRIx16"\n",
                        pdir.pair[0], pdir.pair[1], moveid);
                clfs_fs_prepmove(clfs, 0x3ff, NULL);
                if (moveid < clfs_tag_id(tag)) {
                    tag -= CLFS_MKTAG(0, 1, 0);
                }
            }

            clfs_block_t ppair[2] = {pdir.pair[0], pdir.pair[1]};
            clfs_pair_tole32(ldir.pair);
            state = clfs_dir_relocatingcommit(clfs, &pdir, ppair, CLFS_MKATTRS(
                        {CLFS_MKTAG_IF(moveid != 0x3ff,
                            CLFS_TYPE_DELETE, moveid, 0), NULL},
                        {tag, ldir.pair}),
                    NULL);
            clfs_pair_fromle32(ldir.pair);
            if (state < 0) {
                return state;
            }

            if (state == CLFS_OK_RELOCATED) {
                lpair[0] = ppair[0];
                lpair[1] = ppair[1];
                ldir = pdir;
                orphans = true;
                continue;
            }
        }

        int err = clfs_fs_pred(clfs, lpair, &pdir);
        /*  找到pred  */
        if (err && err != CLFS_ERR_NOENT) {
            return err;
        }
        CLFS_ASSERT(!(hasparent && err == CLFS_ERR_NOENT));

        if (err != CLFS_ERR_NOENT) {
            /*  如果找不到dir，它一定是新的   */
            if (clfs_gstate_hasorphans(&clfs->gstate)) {
                // 下一步，清除孤儿节点
                err = clfs_fs_preporphans(clfs, -hasparent);
                if (err) {
                    return err;
                }
            }
            uint16_t moveid = 0x3ff;
            if (clfs_gstate_hasmovehere(&clfs->gstate, pdir.pair)) {
                moveid = clfs_tag_id(clfs->gstate.tag);
                CLFS_DEBUG("Fixing move while relocating "
                        "{0x%"PRIx32", 0x%"PRIx32"} 0x%"PRIx16"\n",
                        pdir.pair[0], pdir.pair[1], moveid);
                clfs_fs_prepmove(clfs, 0x3ff, NULL);
            }

            lpair[0] = pdir.pair[0];
            lpair[1] = pdir.pair[1];
            clfs_pair_tole32(ldir.pair);
            state = clfs_dir_relocatingcommit(clfs, &pdir, lpair, CLFS_MKATTRS(
                /*  替换坏的pair，要么我们清除不同步，要么不同步发生   */
                        {CLFS_MKTAG_IF(moveid != 0x3ff,
                            CLFS_TYPE_DELETE, moveid, 0), NULL},
                        {CLFS_MKTAG(CLFS_TYPE_TAIL + pdir.split, 0x3ff, 8),
                            ldir.pair}),
                    NULL);
            clfs_pair_fromle32(ldir.pair);
            if (state < 0) {
                return state;
            }

            ldir = pdir;
        }
    }

    return orphans ? CLFS_OK_ORPHANED : 0;
}
#endif

#ifndef CLFS_READONLY /* 向元数据对提交条目 */
static int clfs_dir_commit(clfs_t *clfs, clfs_mdir_t *dir,
        const struct clfs_mattr *attrs, int attrcount) {
    int orphans = clfs_dir_orphaningcommit(clfs, dir, attrs, attrcount);
    if (orphans < 0) {
        return orphans;
    }

    if (orphans) {
        int err = clfs_fs_deorphan(clfs, false);
        if (err) {
            return err;
        }
    }

    return 0;
}
#endif
/*********************************************************************************************************
  顶层目录操作
*********************************************************************************************************/
#ifndef CLFS_READONLY
static int clfs_rawmkdir(clfs_t *clfs, const char *path) {

    int err = clfs_fs_forceconsistency(clfs);
    /*  deorphan如果还没有，在通电后最多需要一次  */
    if (err) {
        return err;
    }

    struct clfs_mlist cwd;
    cwd.next = clfs->mlist;
    uint16_t id;
    err = clfs_dir_find(clfs, &cwd.m, &path, &id);
    if (!(err == CLFS_ERR_NOENT && id != 0x3ff)) {
        return (err < 0) ? err : CLFS_ERR_EXIST;
    }

    clfs_size_t nlen = strlen(path);
    /*  检查名称是否匹配   */
    if (nlen > clfs->name_max) {
        return CLFS_ERR_NAMETOOLONG;
    }

    clfs_alloc_ack(clfs);
    /*  新建目录   */
    clfs_mdir_t dir;
    err = clfs_dir_alloc(clfs, &dir);
    if (err) {
        return err;
    }

    clfs_mdir_t pred = cwd.m;
    /*  查找元数据对列表的末尾   */
    while (pred.split) {
        err = clfs_dir_fetch(clfs, &pred, pred.tail);
        if (err) {
            return err;
        }
    }

    clfs_pair_tole32(pred.tail);
    /*  设置dir   */
    err = clfs_dir_commit(clfs, &dir, CLFS_MKATTRS(
            {CLFS_MKTAG(CLFS_TYPE_SOFTTAIL, 0x3ff, 8), pred.tail}));
    clfs_pair_fromle32(pred.tail);
    if (err) {
        return err;
    }

    if (cwd.m.split) {
        /*  当前块不结束列表   */
        err = clfs_fs_preporphans(clfs, +1);
        if (err) {
            return err;
        }

        cwd.type = 0;
        cwd.id = 0;
        clfs->mlist = &cwd;

        clfs_pair_tole32(dir.pair);
        err = clfs_dir_commit(clfs, &pred, CLFS_MKATTRS(
                {CLFS_MKTAG(CLFS_TYPE_SOFTTAIL, 0x3ff, 8), dir.pair}));
        clfs_pair_fromle32(dir.pair);
        if (err) {
            clfs->mlist = cwd.next;
            return err;
        }

        clfs->mlist = cwd.next;
        err = clfs_fs_preporphans(clfs, -1);
        if (err) {
            return err;
        }
    }

    clfs_pair_tole32(dir.pair);
    /*  插入父块   */
    err = clfs_dir_commit(clfs, &cwd.m, CLFS_MKATTRS(
            {CLFS_MKTAG(CLFS_TYPE_CREATE, id, 0), NULL},
            {CLFS_MKTAG(CLFS_TYPE_DIR, id, nlen), path},
            {CLFS_MKTAG(CLFS_TYPE_DIRSTRUCT, id, 8), dir.pair},
            {CLFS_MKTAG_IF(!cwd.m.split,
                CLFS_TYPE_SOFTTAIL, 0x3ff, 8), dir.pair}));
    clfs_pair_fromle32(dir.pair);
    if (err) {
        return err;
    }

    return 0;
}
#endif

static int clfs_dir_rawopen(clfs_t *clfs, clfs_dir_t *dir, const char *path) {
    /* 根据path和元数据对，得到父目录的tag */
    clfs_stag_t tag = clfs_dir_find(clfs, &dir->m, &path, NULL);
    if (tag < 0) {
        return tag;
    }

    if (clfs_tag_type3(tag) != CLFS_TYPE_DIR) {
        return CLFS_ERR_NOTDIR;
    }

    clfs_block_t pair[2];
    if (clfs_tag_id(tag) == 0x3ff) {
        /*  处理根目录   */
        pair[0] = clfs->root[0];
        pair[1] = clfs->root[1];
    } else {
        /*  从父目录获取当前目录的dir pair  */
        clfs_stag_t res = clfs_dir_get(clfs, &dir->m, CLFS_MKTAG(0x700, 0x3ff, 0),
                CLFS_MKTAG(CLFS_TYPE_STRUCT, clfs_tag_id(tag), 8), pair);
        if (res < 0) {
            return res;
        }
        clfs_pair_fromle32(pair);
    }

    /* 根据dir pair得到当前目录的元数据对块dir->m */
    int err = clfs_dir_fetch(clfs, &dir->m, pair);
    if (err) {
        return err;
    }

    /*  设置目录条目   */
    dir->head[0] = dir->m.pair[0];
    dir->head[1] = dir->m.pair[1];
    dir->id = 0;
    dir->pos = 0;

    /*  添加到元数据列表  */
    dir->type = CLFS_TYPE_DIR;
    clfs_mlist_append(clfs, (struct clfs_mlist *)dir);

    return 0;
}

static int clfs_dir_rawclose(clfs_t *clfs, clfs_dir_t *dir) {
    /*  从元数据列表中删除  */
    clfs_mlist_remove(clfs, (struct clfs_mlist *)dir);

    return 0;
}

static int clfs_dir_rawread(clfs_t *clfs, clfs_dir_t *dir, struct clfs_info *info) {
    memset(info, 0, sizeof(*info));
    if (dir->pos == 0) {
         /*  特殊的偏移"."和".."   */
        info->type = CLFS_TYPE_DIR;
        strcpy(info->name, ".");
        dir->pos += 1;
        return true;
    } else if (dir->pos == 1) {
        info->type = CLFS_TYPE_DIR;
        strcpy(info->name, "..");
        dir->pos += 1;
        return true;
    }

    while (true) {
        if (dir->id == dir->m.count) {
            if (!dir->m.split) {
                return false;
            }

            int err = clfs_dir_fetch(clfs, &dir->m, dir->m.tail);
            if (err) {
                return err;
            }

            dir->id = 0;
        }

        int err = clfs_dir_getinfo(clfs, &dir->m, dir->id, info);
        if (err && err != CLFS_ERR_NOENT) {
            return err;
        }

        dir->id += 1;
        if (err != CLFS_ERR_NOENT) {
            break;
        }
    }

    dir->pos += 1;
    return true;
}

static int clfs_dir_rawseek(clfs_t *clfs, clfs_dir_t *dir, clfs_off_t off) {
    /* 回到目录开头 */
    int err = clfs_dir_rawrewind(clfs, dir);
    if (err) {
        return err;
    }

    dir->pos = clfs_min(2, off);
    off -= dir->pos;

    dir->id = (off > 0 && clfs_pair_cmp(dir->head, clfs->root) == 0);
    /*   跳过超级块条目  */

    while (off > 0) {
        int diff = clfs_min(dir->m.count - dir->id, off);
        dir->id += diff;
        dir->pos += diff;
        off -= diff;

        if (dir->id == dir->m.count) {
            /*该目录数据被放到了下一对块上*/
            if (!dir->m.split) {
                return CLFS_ERR_INVAL;
            }

            err = clfs_dir_fetch(clfs, &dir->m, dir->m.tail);
            if (err) {
                return err;
            }

            dir->id = 0;
        }
    }

    return 0;
}

// 返回目录当前指针位置
static clfs_soff_t clfs_dir_rawtell(clfs_t *clfs, clfs_dir_t *dir) {
    (void)clfs;
    return dir->pos;
}

// 重新读取目录，指针设为首部
static int clfs_dir_rawrewind(clfs_t *clfs, clfs_dir_t *dir) {
    /*  重新加载头目录  */
    int err = clfs_dir_fetch(clfs, &dir->m, dir->head);
    if (err) {
        return err;
    }

    dir->id = 0;
    dir->pos = 0;
    return 0;
}

/*********************************************************************************************************
  文件索引列表操作
*********************************************************************************************************/
static int clfs_ctz_index(clfs_t *clfs, clfs_off_t *off) {
    clfs_off_t size = *off;
    clfs_off_t b = clfs->cfg->block_size - 2*4;
    clfs_off_t i = size / b;
    if (i == 0) {
        return 0;
    }

    i = (size - 4*(clfs_popc(i-1)+2)) / b;
    *off = size - b*i - 4*clfs_popc(i);
    return i;
}

static int clfs_ctz_find(clfs_t *clfs,
        const clfs_cache_t *pcache, clfs_cache_t *rcache,
        clfs_block_t head, clfs_size_t size,
        clfs_size_t pos, clfs_block_t *block, clfs_off_t *off) {
    if (size == 0) {
        *block = CLFS_BLOCK_NULL;
        *off = 0;
        return 0;
    }

    clfs_off_t current = clfs_ctz_index(clfs, &(clfs_off_t){size-1});
    clfs_off_t target = clfs_ctz_index(clfs, &pos);

    while (current > target) {
        clfs_size_t skip = clfs_min(
                clfs_npw2(current-target+1) - 1,
                clfs_ctz(current));

        int err = clfs_bd_read(clfs,
                pcache, rcache, sizeof(head),
                head, 4*skip, &head, sizeof(head));
        head = clfs_fromle32(head);
        if (err) {
            return err;
        }

        current -= 1 << skip;
    }

    *block = head;
    *off = pos;
    return 0;
}

#ifndef CLFS_READONLY
static int clfs_ctz_extend(clfs_t *clfs,
        clfs_cache_t *pcache, clfs_cache_t *rcache,
        clfs_block_t head, clfs_size_t size,
        clfs_block_t *block, clfs_off_t *off) {
    while (true) {
        clfs_block_t nblock;
        /*  继续抓取一个block   */
        int err = clfs_alloc(clfs, &nblock);
        if (err) {
            return err;
        }

        {
            err = clfs_bd_erase(clfs, nblock);
            if (err) {
                if (err == CLFS_ERR_CORRUPT) {
                    goto relocate;
                }
                return err;
            }

            if (size == 0) {
                *block = nblock;
                *off = 0;
                return 0;
            }

            clfs_size_t noff = size - 1;
            clfs_off_t index = clfs_ctz_index(clfs, &noff);
            noff = noff + 1;

            if (noff != clfs->cfg->block_size) {
                /*  复制最后一个块，如果它是不完整的  */
                clfs_off_t i;
                for (i = 0; i < noff; i++) {
                    uint8_t data;
                    err = clfs_bd_read(clfs,
                            NULL, rcache, noff-i,
                            head, i, &data, 1);
                    if (err) {
                        return err;
                    }

                    err = clfs_bd_prog(clfs,
                            pcache, rcache, true,
                            nblock, i, &data, 1);
                    if (err) {
                        if (err == CLFS_ERR_CORRUPT) {
                            goto relocate;
                        }
                        return err;
                    }
                }

                *block = nblock;
                *off = noff;
                return 0;
            }

            index += 1;
            /*  添加块   */
            clfs_size_t skips = clfs_ctz(index) + 1;
            clfs_block_t nhead = head;
            clfs_off_t i;
            for (i = 0; i < skips; i++) {
                nhead = clfs_tole32(nhead);
                err = clfs_bd_prog(clfs, pcache, rcache, true,
                        nblock, 4*i, &nhead, 4);
                nhead = clfs_fromle32(nhead);
                if (err) {
                    if (err == CLFS_ERR_CORRUPT) {
                        goto relocate;
                    }
                    return err;
                }

                if (i != skips-1) {
                    err = clfs_bd_read(clfs,
                            NULL, rcache, sizeof(nhead),
                            nhead, 4*i, &nhead, sizeof(nhead));
                    nhead = clfs_fromle32(nhead);
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
        CLFS_DEBUG("Bad block at 0x%"PRIx32, nblock);
        clfs_cache_drop(clfs, pcache);
        /*  清理缓存并尝试新的块   */
    }
}
#endif

static int clfs_ctz_traverse(clfs_t *clfs,
        const clfs_cache_t *pcache, clfs_cache_t *rcache,
        clfs_block_t head, clfs_size_t size,
        int (*cb)(void*, clfs_block_t), void *data) {
    if (size == 0) {
        return 0;
    }

    clfs_off_t index = clfs_ctz_index(clfs, &(clfs_off_t){size-1});

    while (true) {
        int err = cb(data, head);
        if (err) {
            return err;
        }

        if (index == 0) {
            return 0;
        }

        clfs_block_t heads[2];
        int count = 2 - (index & 1);
        err = clfs_bd_read(clfs,
                pcache, rcache, count*sizeof(head),
                head, 0, &heads, count*sizeof(head));
        heads[0] = clfs_fromle32(heads[0]);
        heads[1] = clfs_fromle32(heads[1]);
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
  顶层文件操作
*********************************************************************************************************/
static int clfs_file_rawopencfg(clfs_t *clfs, clfs_file_t *file,
        const char *path, int flags,
        const struct clfs_file_config *cfg) {
#ifndef CLFS_READONLY
    if ((flags & CLFS_O_WRONLY) == CLFS_O_WRONLY) {
        /*  deorphan如果还没有，在通电后最多需要一次  */
        int err = clfs_fs_forceconsistency(clfs);
        if (err) {
            return err;
        }
    }
#else
    CLFS_ASSERT((flags & CLFS_O_RDONLY) == CLFS_O_RDONLY);
#endif

    int err;
    /*  设置简单的文件细节   */
    file->cfg = cfg;
    file->flags = flags;
    file->pos = 0;
    file->off = 0;
    file->cache.buffer = NULL;

    clfs_stag_t tag = clfs_dir_find(clfs, &file->m, &path, &file->id);
    /*  为文件分配不存在的条目   */
    if (tag < 0 && !(tag == CLFS_ERR_NOENT && file->id != 0x3ff)) {
        err = tag;
        goto cleanup;
    }

    file->type = CLFS_TYPE_REG;
    /*  获取id，添加到元数据列表，以捕捉更新的变化   */
    clfs_mlist_append(clfs, (struct clfs_mlist *)file);

#ifdef CLFS_READONLY
    if (tag == CLFS_ERR_NOENT) {
        err = CLFS_ERR_NOENT;
        goto cleanup;
#else
    if (tag == CLFS_ERR_NOENT) {
        if (!(flags & CLFS_O_CREAT)) {
            err = CLFS_ERR_NOENT;
            goto cleanup;
        }

        clfs_size_t nlen = strlen(path);
        /*  检查名称是否匹配   */
        if (nlen > clfs->name_max) {
            err = CLFS_ERR_NAMETOOLONG;
            goto cleanup;
        }

        err = clfs_dir_commit(clfs, &file->m, CLFS_MKATTRS(
            /*  获取下一个槽并创建条目来记住name   */
                {CLFS_MKTAG(CLFS_TYPE_CREATE, file->id, 0), NULL},
                {CLFS_MKTAG(CLFS_TYPE_REG, file->id, nlen), path},
                {CLFS_MKTAG(CLFS_TYPE_INLINESTRUCT, file->id, 0), NULL}));

        err = (err == CLFS_ERR_NOSPC) ? CLFS_ERR_NAMETOOLONG : err;
        if (err) {
            goto cleanup;
        }

        tag = CLFS_MKTAG(CLFS_TYPE_INLINESTRUCT, 0, 0);
    } else if (flags & CLFS_O_EXCL) {
        err = CLFS_ERR_EXIST;
        goto cleanup;
#endif
    } else if (clfs_tag_type3(tag) != CLFS_TYPE_REG) {
        err = CLFS_ERR_ISDIR;
        goto cleanup;
#ifndef CLFS_READONLY
    } else if (flags & CLFS_O_TRUNC) {
        /*  如果请求截断   */
        tag = CLFS_MKTAG(CLFS_TYPE_INLINESTRUCT, file->id, 0);
        file->flags |= CLFS_F_DIRTY;
#endif
    } else {
        tag = clfs_dir_get(clfs, &file->m, CLFS_MKTAG(0x700, 0x3ff, 0),
        /*  尝试加载磁盘上的内容，如果它是内联的，将稍后修复它   */
                CLFS_MKTAG(CLFS_TYPE_STRUCT, file->id, 8), &file->ctz);
        if (tag < 0) {
            err = tag;
            goto cleanup;
        }
        clfs_ctz_fromle32(&file->ctz);
    }

    /*  获取attrs  */
    unsigned i;
    for (i = 0; i < file->cfg->attr_count; i++) {
        if ((file->flags & CLFS_O_RDONLY) == CLFS_O_RDONLY) {
            /*   如果为读写操作打开  */
            clfs_stag_t res = clfs_dir_get(clfs, &file->m,
                    CLFS_MKTAG(0x7ff, 0x3ff, 0),
                    CLFS_MKTAG(CLFS_TYPE_USERATTR + file->cfg->attrs[i].type,
                        file->id, file->cfg->attrs[i].size),
                        file->cfg->attrs[i].buffer);
            if (res < 0 && res != CLFS_ERR_NOENT) {
                err = res;
                goto cleanup;
            }
        }

#ifndef CLFS_READONLY
        if ((file->flags & CLFS_O_WRONLY) == CLFS_O_WRONLY) {
            /*  如果为写/读写操作打开   */
            if (file->cfg->attrs[i].size > clfs->attr_max) {
                err = CLFS_ERR_NOSPC;
                goto cleanup;
            }

            file->flags |= CLFS_F_DIRTY;
        }
#endif
    }

    if (file->cfg->buffer) {
        /*  如果需要，分配缓冲区   */
        file->cache.buffer = file->cfg->buffer;
    } else {
        file->cache.buffer = clfs_malloc(clfs->cfg->cache_size);
        if (!file->cache.buffer) {
            err = CLFS_ERR_NOMEM;
            goto cleanup;
        }
    }

    clfs_cache_zero(clfs, &file->cache);
    /* 置零，以避免信息泄露  */

    if (clfs_tag_type3(tag) == CLFS_TYPE_INLINESTRUCT) {
        file->ctz.head = CLFS_BLOCK_INLINE;   /*  加载内联文件   */
        file->ctz.size = clfs_tag_size(tag);
        file->flags |= CLFS_F_INLINE;
        file->cache.block = file->ctz.head;
        file->cache.off = 0;
        file->cache.size = clfs->cfg->cache_size;

        if (file->ctz.size > 0) {
            /* 不总是读取    */
            clfs_stag_t res = clfs_dir_get(clfs, &file->m,
                    CLFS_MKTAG(0x700, 0x3ff, 0),
                    CLFS_MKTAG(CLFS_TYPE_STRUCT, file->id,
                        clfs_min(file->cache.size, 0x3fe)),
                    file->cache.buffer);
            if (res < 0) {
                err = res;
                goto cleanup;
            }
        }
    }

    return 0;

cleanup:  /* 清理残留资源    */
#ifndef CLFS_READONLY
    file->flags |= CLFS_F_ERRED;
#endif
    clfs_file_rawclose(clfs, file);
    return err;
}

static int clfs_file_rawopen(clfs_t *clfs, clfs_file_t *file,
        const char *path, int flags) {
    static const struct clfs_file_config defaults = {0};
    int err = clfs_file_rawopencfg(clfs, file, path, flags, &defaults);
    return err;
}

static int clfs_file_rawclose(clfs_t *clfs, clfs_file_t *file) {
#ifndef CLFS_READONLY
    int err = clfs_file_rawsync(clfs, file);
#else
    int err = 0;
#endif
    /*  从元数据列表中删除   */
    clfs_mlist_remove(clfs, (struct clfs_mlist*)file);

    if (!file->cfg->buffer) { /*   清理内存  */
        clfs_free(file->cache.buffer);
    }

    return err;
}


#ifndef CLFS_READONLY
static int clfs_file_relocate(clfs_t *clfs, clfs_file_t *file) {
    while (true) {
        clfs_block_t nblock;
        /*  重新定位到新的块   */
        int err = clfs_alloc(clfs, &nblock);
        if (err) {
            return err;
        }

        err = clfs_bd_erase(clfs, nblock);
        if (err) {
            if (err == CLFS_ERR_CORRUPT) {
                goto relocate;
            }
            return err;
        }

        clfs_off_t i;
        /*  从脏缓存或磁盘读取   */
        for (i = 0; i < file->off; i++) {
            uint8_t data;
            if (file->flags & CLFS_F_INLINE) {
                err = clfs_dir_getread(clfs, &file->m,
                        NULL, &file->cache, file->off-i,  /*  在内联文件变成脏文件之前将其清除   */
                        CLFS_MKTAG(0xfff, 0x1ff, 0),
                        CLFS_MKTAG(CLFS_TYPE_INLINESTRUCT, file->id, 0),
                        i, &data, 1);
                if (err) {
                    return err;
                }
            } else {
                err = clfs_bd_read(clfs,
                        &file->cache, &clfs->rcache, file->off-i,
                        file->block, i, &data, 1);
                if (err) {
                    return err;
                }
            }

            err = clfs_bd_prog(clfs,
                    &clfs->pcache, &clfs->rcache, true,
                    nblock, i, &data, 1);
            if (err) {
                if (err == CLFS_ERR_CORRUPT) {
                    goto relocate;
                }
                return err;
            }
        }

        /*  复制文件的新状态   */
        memcpy(file->cache.buffer, clfs->pcache.buffer, clfs->cfg->cache_size);

        file->cache.block = clfs->pcache.block;
        file->cache.off = clfs->pcache.off;
        file->cache.size = clfs->pcache.size;
        clfs_cache_zero(clfs, &clfs->pcache);

        file->block = nblock;
        file->flags |= CLFS_F_WRITING;
        return 0;

relocate:
        CLFS_DEBUG("Bad block at 0x%"PRIx32, nblock);

        clfs_cache_drop(clfs, &clfs->pcache);
        /*  清理缓存并尝试新的块   */
    }
}
#endif

#ifndef CLFS_READONLY
static int clfs_file_outline(clfs_t *clfs, clfs_file_t *file) {
    file->off = file->pos;
    clfs_alloc_ack(clfs);
    int err = clfs_file_relocate(clfs, file);
    if (err) {
        return err;
    }

    file->flags &= ~CLFS_F_INLINE;
    return 0;
}
#endif

static int clfs_file_flush(clfs_t *clfs, clfs_file_t *file) {
    if (file->flags & CLFS_F_READING) {
        if (!(file->flags & CLFS_F_INLINE)) {
            clfs_cache_drop(clfs, &file->cache);
        }
        file->flags &= ~CLFS_F_READING;
    }

#ifndef CLFS_READONLY
    if (file->flags & CLFS_F_WRITING) {
        clfs_off_t pos = file->pos;
        if (!(file->flags & CLFS_F_INLINE)) {
            clfs_file_t orig = {
                /*  复制当前分支之后的任何内容   */
                .ctz.head = file->ctz.head,
                .ctz.size = file->ctz.size,
                .flags = CLFS_O_RDONLY,
                .pos = file->pos,
                .cache = clfs->rcache,
            };
            clfs_cache_drop(clfs, &clfs->rcache);

            while (file->pos < file->ctz.size) {
                uint8_t data;
                /* 每次复制一个字节    */
                clfs_ssize_t res = clfs_file_flushedread(clfs, &orig, &data, 1);
                if (res < 0) {
                    return res;
                }

                res = clfs_file_flushedwrite(clfs, file, &data, 1);
                if (res < 0) {
                    return res;
                }

                if (clfs->rcache.block != CLFS_BLOCK_NULL) {
                    clfs_cache_drop(clfs, &orig.cache);
                    clfs_cache_drop(clfs, &clfs->rcache);
                }
            }

            while (true) {
                int err = clfs_bd_flush(clfs, &file->cache, &clfs->rcache, true);
                if (err) {
                    if (err == CLFS_ERR_CORRUPT) {
                        goto relocate;
                    }
                    return err;
                }

                break;

relocate:
                CLFS_DEBUG("Bad block at 0x%"PRIx32, file->block);
                err = clfs_file_relocate(clfs, file);
                if (err) {
                    return err;
                }
            }
        } else {
            file->pos = clfs_max(file->pos, file->ctz.size);
        }

        file->ctz.head = file->block;
        /*  实际文件更新   */
        file->ctz.size = file->pos;
        file->flags &= ~CLFS_F_WRITING;
        file->flags |= CLFS_F_DIRTY;

        file->pos = pos;
    }
#endif

    return 0;
}

#ifndef CLFS_READONLY
static int clfs_file_rawsync(clfs_t *clfs, clfs_file_t *file) {
    if (file->flags & CLFS_F_ERRED) {
        return 0;
    }

    int err = clfs_file_flush(clfs, file);
    if (err) {
        file->flags |= CLFS_F_ERRED;
        return err;
    }


    if ((file->flags & CLFS_F_DIRTY) &&
            !clfs_pair_isnull(file->m.pair)) {
        uint16_t type;
        /* 更新目录条目   */
        const void *buffer;
        clfs_size_t size;
        struct clfs_ctz ctz;
        if (file->flags & CLFS_F_INLINE) {
            type = CLFS_TYPE_INLINESTRUCT;
            /*   内联整个文件  */
            buffer = file->cache.buffer;
            size = file->ctz.size;
        } else {
            type = CLFS_TYPE_CTZSTRUCT;
            /*  更新CTZ引用   */
            ctz = file->ctz;
            /*  复制CTZ，使alloc在重新定位期间工作   */
            clfs_ctz_tole32(&ctz);
            buffer = &ctz;
            size = sizeof(ctz);
        }


        err = clfs_dir_commit(clfs, &file->m, CLFS_MKATTRS(
            /*  提交文件数据和属性   */
                {CLFS_MKTAG(type, file->id, size), buffer},
                {CLFS_MKTAG(CLFS_FROM_USERATTRS, file->id,
                    file->cfg->attr_count), file->cfg->attrs}));
        if (err) {
            file->flags |= CLFS_F_ERRED;
            return err;
        }

        file->flags &= ~CLFS_F_DIRTY;
    }

    return 0;
}
#endif

static clfs_ssize_t clfs_file_flushedread(clfs_t *clfs, clfs_file_t *file,
        void *buffer, clfs_size_t size) {
    uint8_t *data = buffer;
    clfs_size_t nsize = size;

    if (file->pos >= file->ctz.size) {
        return 0;
    }

    size = clfs_min(size, file->ctz.size - file->pos);
    nsize = size;

    while (nsize > 0) {
        if (!(file->flags & CLFS_F_READING) ||
                file->off == clfs->cfg->block_size) {
                    /*  检查是否需要一个新的块   */
            if (!(file->flags & CLFS_F_INLINE)) {
                int err = clfs_ctz_find(clfs, NULL, &file->cache,
                        file->ctz.head, file->ctz.size,
                        file->pos, &file->block, &file->off);
                if (err) {
                    return err;
                }
            } else {
                file->block = CLFS_BLOCK_INLINE;
                file->off = file->pos;
            }

            file->flags |= CLFS_F_READING;
        }

        clfs_size_t diff = clfs_min(nsize, clfs->cfg->block_size - file->off);
        /*   在当前块中读取尽可能多的数据  */
        if (file->flags & CLFS_F_INLINE) {
            int err = clfs_dir_getread(clfs, &file->m,
                    NULL, &file->cache, clfs->cfg->block_size,
                    CLFS_MKTAG(0xfff, 0x1ff, 0),
                    CLFS_MKTAG(CLFS_TYPE_INLINESTRUCT, file->id, 0),
                    file->off, data, diff);
            if (err) {
                return err;
            }
        } else {
            int err = clfs_bd_read(clfs,
                    NULL, &file->cache, clfs->cfg->block_size,
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

static clfs_ssize_t clfs_file_rawread(clfs_t *clfs, clfs_file_t *file,
        void *buffer, clfs_size_t size) {
    CLFS_ASSERT((file->flags & CLFS_O_RDONLY) == CLFS_O_RDONLY);

#ifndef CLFS_READONLY
    if (file->flags & CLFS_F_WRITING) {

        int err = clfs_file_flush(clfs, file);
        /*  清除所有写入操作   */
        if (err) {
            return err;
        }
    }
#endif

    return clfs_file_flushedread(clfs, file, buffer, size);
}


#ifndef CLFS_READONLY
static clfs_ssize_t clfs_file_flushedwrite(clfs_t *clfs, clfs_file_t *file,
        const void *buffer, clfs_size_t size) {
    const uint8_t *data = buffer;
    clfs_size_t nsize = size;

    if ((file->flags & CLFS_F_INLINE) &&
            clfs_max(file->pos+nsize, file->ctz.size) >
            clfs_min(0x3fe, clfs_min(
                clfs->cfg->cache_size,
                (clfs->cfg->metadata_max ?
                    clfs->cfg->metadata_max : clfs->cfg->block_size) / 8))) {
        int err = clfs_file_outline(clfs, file);
        /*  内联文件不再适合   */
        if (err) {
            file->flags |= CLFS_F_ERRED;
            return err;
        }
    }

    while (nsize > 0) {
        if (!(file->flags & CLFS_F_WRITING) ||
                file->off == clfs->cfg->block_size) {
                    /*  检查我们是否需要一个新的块   */
            if (!(file->flags & CLFS_F_INLINE)) {
                if (!(file->flags & CLFS_F_WRITING) && file->pos > 0) {
                    int err = clfs_ctz_find(clfs, NULL, &file->cache,
                    /*  找出我们从哪个块扩展   */
                            file->ctz.head, file->ctz.size,
                            file->pos-1, &file->block, &file->off);
                    if (err) {
                        file->flags |= CLFS_F_ERRED;
                        return err;
                    }

                    clfs_cache_zero(clfs, &file->cache);
                    /*  将cache标记为dirty，因为我们可能已经向cache中读取了数据   */
                }

                clfs_alloc_ack(clfs);
                /*  扩展文件与新的块   */
                int err = clfs_ctz_extend(clfs, &file->cache, &clfs->rcache,
                        file->block, file->pos,
                        &file->block, &file->off);
                if (err) {
                    file->flags |= CLFS_F_ERRED;
                    return err;
                }
            } else {
                file->block = CLFS_BLOCK_INLINE;
                file->off = file->pos;
            }

            file->flags |= CLFS_F_WRITING;
        }

        clfs_size_t diff = clfs_min(nsize, clfs->cfg->block_size - file->off);
        /*  在当前块中尽可能多地写入   */
        while (true) {
            int err = clfs_bd_prog(clfs, &file->cache, &clfs->rcache, true,
                    file->block, file->off, data, diff);
            if (err) {
                if (err == CLFS_ERR_CORRUPT) {
                    goto relocate;
                }
                file->flags |= CLFS_F_ERRED;
                return err;
            }

            break;
relocate:
            err = clfs_file_relocate(clfs, file);
            if (err) {
                file->flags |= CLFS_F_ERRED;
                return err;
            }
        }

        file->pos += diff;
        file->off += diff;
        data += diff;
        nsize -= diff;

        clfs_alloc_ack(clfs);
    }

    return size;
}

static clfs_ssize_t clfs_file_rawwrite(clfs_t *clfs, clfs_file_t *file,
        const void *buffer, clfs_size_t size) {
    CLFS_ASSERT((file->flags & CLFS_O_WRONLY) == CLFS_O_WRONLY);

    if (file->flags & CLFS_F_READING) {
        int err = clfs_file_flush(clfs, file);
        /*  删除任何读取   */
        if (err) {
            return err;
        }
    }

    if ((file->flags & CLFS_O_APPEND) && file->pos < file->ctz.size) {
        file->pos = file->ctz.size;
    }

    if (file->pos + size > clfs->file_max) {
        /*  文件大小超过限制   */
        return CLFS_ERR_FBIG;
    }

    if (!(file->flags & CLFS_F_WRITING) && file->pos > file->ctz.size) {
        clfs_off_t pos = file->pos;
        /* 填充0    */
        file->pos = file->ctz.size;

        while (file->pos < pos) {
            clfs_ssize_t res = clfs_file_flushedwrite(clfs, file, &(uint8_t){0}, 1);
            if (res < 0) {
                return res;
            }
        }
    }

    clfs_ssize_t nsize = clfs_file_flushedwrite(clfs, file, buffer, size);
    if (nsize < 0) {
        return nsize;
    }

    file->flags &= ~CLFS_F_ERRED;
    return nsize;
}
#endif

static clfs_soff_t clfs_file_rawseek(clfs_t *clfs, clfs_file_t *file,
        clfs_soff_t off, int whence) {
    clfs_off_t npos = file->pos;
    /*  寻找新的pos   */
    if (whence == CLFS_SEEK_SET) {
        npos = off;
    } else if (whence == CLFS_SEEK_CUR) {
        if ((clfs_soff_t)file->pos + off < 0) {
            return CLFS_ERR_INVAL;
        } else {
            npos = file->pos + off;
        }
    } else if (whence == CLFS_SEEK_END) {
        clfs_soff_t res = clfs_file_rawsize(clfs, file) + off;
        if (res < 0) {
            return CLFS_ERR_INVAL;
        } else {
            npos = res;
        }
    }

    if (npos > clfs->file_max) {
        /*  文件位置超出范围   */
        return CLFS_ERR_INVAL;
    }

    if (file->pos == npos) {
        return npos;
    }

    if (
#ifndef CLFS_READONLY
        !(file->flags & CLFS_F_WRITING)
#else
        true
#endif
            ) {
        int oindex = clfs_ctz_index(clfs, &(clfs_off_t){file->pos});
        clfs_off_t noff = npos;
        int nindex = clfs_ctz_index(clfs, &noff);
        if (oindex == nindex
                && noff >= file->cache.off
                && noff < file->cache.off + file->cache.size) {
            file->pos = npos;
            file->off = noff;
            return npos;
        }
    }


    int err = clfs_file_flush(clfs, file);
    /*   预先写出所有内容  */
    if (err) {
        return err;
    }

    file->pos = npos;
    /*  更新pos   */
    return npos;
}

#ifndef CLFS_READONLY
static int clfs_file_rawtruncate(clfs_t *clfs, clfs_file_t *file, clfs_off_t size) {
    CLFS_ASSERT((file->flags & CLFS_O_WRONLY) == CLFS_O_WRONLY);

    if (size > CLFS_FILE_MAX) {
        return CLFS_ERR_INVAL;
    }

    clfs_off_t pos = file->pos;
    clfs_off_t oldsize = clfs_file_rawsize(clfs, file);
    if (size < oldsize) {
        int err = clfs_file_flush(clfs, file);
        /*  需要刷新，因为直接更改了元数据   */
        if (err) {
            return err;
        }

        err = clfs_ctz_find(clfs, NULL, &file->cache,
        /*  在CTZ跳跃表中查找新的头   */
                file->ctz.head, file->ctz.size,
                size, &file->block, &file->off);
        if (err) {
            return err;
        }

        file->pos = size;
        file->ctz.head = file->block;
        file->ctz.size = size;
        file->flags |= CLFS_F_DIRTY | CLFS_F_READING;
    } else if (size > oldsize) {
        clfs_soff_t res = clfs_file_rawseek(clfs, file, 0, CLFS_SEEK_END);
        /*  flush+seek如果还没有结束   */
        if (res < 0) {
            return (int)res;
        }


        while (file->pos < size) {
            /*   填充0  */
            res = clfs_file_rawwrite(clfs, file, &(uint8_t){0}, 1);
            if (res < 0) {
                return (int)res;
            }
        }
    }

    clfs_soff_t res = clfs_file_rawseek(clfs, file, pos, CLFS_SEEK_SET);
    /*  恢复pos   */
    if (res < 0) {
      return (int)res;
    }

    return 0;
}
#endif

static clfs_soff_t clfs_file_rawtell(clfs_t *clfs, clfs_file_t *file) {
    (void)clfs;
    return file->pos;
}

static int clfs_file_rawrewind(clfs_t *clfs, clfs_file_t *file) {
    clfs_soff_t res = clfs_file_rawseek(clfs, file, 0, CLFS_SEEK_SET);
    if (res < 0) {
        return (int)res;
    }

    return 0;
}

static clfs_soff_t clfs_file_rawsize(clfs_t *clfs, clfs_file_t *file) {
    (void)clfs;

#ifndef CLFS_READONLY
    if (file->flags & CLFS_F_WRITING) {
        return clfs_max(file->pos, file->ctz.size);
    }
#endif

    return file->ctz.size;
}

/*********************************************************************************************************
     一般操作
*********************************************************************************************************/
static int clfs_rawstat(clfs_t *clfs, const char *path, struct clfs_info *info) {
    clfs_mdir_t cwd;
    clfs_stag_t tag = clfs_dir_find(clfs, &cwd, &path, NULL);
    if (tag < 0) {
        return (int)tag;
    }

    return clfs_dir_getinfo(clfs, &cwd, clfs_tag_id(tag), info);
}

#ifndef CLFS_READONLY
static int clfs_rawremove(clfs_t *clfs, const char *path) {
    int err = clfs_fs_forceconsistency(clfs);
    if (err) {
        return err;
    }

    clfs_mdir_t cwd;
    clfs_stag_t tag = clfs_dir_find(clfs, &cwd, &path, NULL);
    if (tag < 0 || clfs_tag_id(tag) == 0x3ff) {
        return (tag < 0) ? (int)tag : CLFS_ERR_INVAL;
    }

    struct clfs_mlist dir;
    dir.next = clfs->mlist;
    if (clfs_tag_type3(tag) == CLFS_TYPE_DIR) {
        clfs_block_t pair[2];
        /*   必须为空  */
        clfs_stag_t res = clfs_dir_get(clfs, &cwd, CLFS_MKTAG(0x700, 0x3ff, 0),
                CLFS_MKTAG(CLFS_TYPE_STRUCT, clfs_tag_id(tag), 8), pair);
        if (res < 0) {
            return (int)res;
        }
        clfs_pair_fromle32(pair);

        err = clfs_dir_fetch(clfs, &dir.m, pair);
        if (err) {
            return err;
        }

        if (dir.m.count > 0 || dir.m.split) {
            return CLFS_ERR_NOTEMPTY;
        }

        err = clfs_fs_preporphans(clfs, +1);
        /*  将文件系统标记为孤立的   */
        if (err) {
            return err;
        }

        dir.type = 0;
        dir.id = 0;
        clfs->mlist = &dir;
    }

    err = clfs_dir_commit(clfs, &cwd, CLFS_MKATTRS(
        /*  删除该条目   */
            {CLFS_MKTAG(CLFS_TYPE_DELETE, clfs_tag_id(tag), 0), NULL}));
    if (err) {
        clfs->mlist = dir.next;
        return err;
    }

    clfs->mlist = dir.next;
    if (clfs_tag_type3(tag) == CLFS_TYPE_DIR) {
        err = clfs_fs_preporphans(clfs, -1);
        /*  固定孤儿   */
        if (err) {
            return err;
        }

        err = clfs_fs_pred(clfs, dir.m.pair, &cwd);
        if (err) {
            return err;
        }

        err = clfs_dir_drop(clfs, &cwd, &dir.m);
        if (err) {
            return err;
        }
    }

    return 0;
}
#endif

#ifndef CLFS_READONLY
static int clfs_rawrename(clfs_t *clfs, const char *oldpath, const char *newpath) {
    int err = clfs_fs_forceconsistency(clfs);
    /*  在通电后最多需要一次   */
    if (err) {
        return err;
    }

    clfs_mdir_t oldcwd;
    clfs_stag_t oldtag = clfs_dir_find(clfs, &oldcwd, &oldpath, NULL);
    /* 查找旧条目    */
    if (oldtag < 0 || clfs_tag_id(oldtag) == 0x3ff) {
        return (oldtag < 0) ? (int)oldtag : CLFS_ERR_INVAL;
    }

    clfs_mdir_t newcwd;
    uint16_t newid;
    clfs_stag_t prevtag = clfs_dir_find(clfs, &newcwd, &newpath, &newid);
    /*  找到新的条目   */
    if ((prevtag < 0 || clfs_tag_id(prevtag) == 0x3ff) &&
            !(prevtag == CLFS_ERR_NOENT && newid != 0x3ff)) {
        return (prevtag < 0) ? (int)prevtag : CLFS_ERR_INVAL;
    }

    /*   特殊的情况  */
    bool samepair = (clfs_pair_cmp(oldcwd.pair, newcwd.pair) == 0);
    uint16_t newoldid = clfs_tag_id(oldtag);

    struct clfs_mlist prevdir;
    prevdir.next = clfs->mlist;
    if (prevtag == CLFS_ERR_NOENT) {
        clfs_size_t nlen = strlen(newpath);
        /*  检查名称是否匹配  */
        if (nlen > clfs->name_max) {
            return CLFS_ERR_NAMETOOLONG;
        }

        if (samepair && newid <= newoldid) {
            newoldid += 1;
        }
    } else if (clfs_tag_type3(prevtag) != clfs_tag_type3(oldtag)) {
        return CLFS_ERR_ISDIR;
    } else if (samepair && newid == newoldid) {
        return 0;
    } else if (clfs_tag_type3(prevtag) == CLFS_TYPE_DIR) {
        /*  必须为空   */
        clfs_block_t prevpair[2];
        clfs_stag_t res = clfs_dir_get(clfs, &newcwd, CLFS_MKTAG(0x700, 0x3ff, 0),
                CLFS_MKTAG(CLFS_TYPE_STRUCT, newid, 8), prevpair);
        if (res < 0) {
            return (int)res;
        }
        clfs_pair_fromle32(prevpair);


        err = clfs_dir_fetch(clfs, &prevdir.m, prevpair);
        /*  必须为空   */
        if (err) {
            return err;
        }

        if (prevdir.m.count > 0 || prevdir.m.split) {
            return CLFS_ERR_NOTEMPTY;
        }

        err = clfs_fs_preporphans(clfs, +1);
        /*  将文件系统标记为孤立的进入翻译页面   */
        if (err) {
            return err;
        }


        /*  dir可以被父母更改   */
        prevdir.type = 0;
        prevdir.id = 0;
        clfs->mlist = &prevdir;
    }

    if (!samepair) {
        clfs_fs_prepmove(clfs, newoldid, oldcwd.pair);
    }


    err = clfs_dir_commit(clfs, &newcwd, CLFS_MKATTRS(
        /*  移动所有属性   */
            {CLFS_MKTAG_IF(prevtag != CLFS_ERR_NOENT,
                CLFS_TYPE_DELETE, newid, 0), NULL},
            {CLFS_MKTAG(CLFS_TYPE_CREATE, newid, 0), NULL},
            {CLFS_MKTAG(clfs_tag_type3(oldtag), newid, strlen(newpath)), newpath},
            {CLFS_MKTAG(CLFS_FROM_MOVE, newid, clfs_tag_id(oldtag)), &oldcwd},
            {CLFS_MKTAG_IF(samepair,
                CLFS_TYPE_DELETE, newoldid, 0), NULL}));
    if (err) {
        clfs->mlist = prevdir.next;
        return err;
    }

    if (!samepair && clfs_gstate_hasmove(&clfs->gstate)) {
        /*   准备gstate并删除moveid  */

        clfs_fs_prepmove(clfs, 0x3ff, NULL);
        err = clfs_dir_commit(clfs, &oldcwd, CLFS_MKATTRS(
                {CLFS_MKTAG(CLFS_TYPE_DELETE, clfs_tag_id(oldtag), 0), NULL}));
        if (err) {
            clfs->mlist = prevdir.next;
            return err;
        }
    }

    clfs->mlist = prevdir.next;
    if (prevtag != CLFS_ERR_NOENT
            && clfs_tag_type3(prevtag) == CLFS_TYPE_DIR) {
        err = clfs_fs_preporphans(clfs, -1);
        /*  固定孤儿   */
        if (err) {
            return err;
        }

        err = clfs_fs_pred(clfs, prevdir.m.pair, &newcwd);
        if (err) {
            return err;
        }

        err = clfs_dir_drop(clfs, &newcwd, &prevdir.m);
        if (err) {
            return err;
        }
    }

    return 0;
}
#endif

static clfs_ssize_t clfs_rawgetattr(clfs_t *clfs, const char *path,
        uint8_t type, void *buffer, clfs_size_t size) {
    clfs_mdir_t cwd;
    clfs_stag_t tag = clfs_dir_find(clfs, &cwd, &path, NULL);
    if (tag < 0) {
        return tag;
    }

    uint16_t id = clfs_tag_id(tag);
    if (id == 0x3ff) {
        id = 0;
        int err = clfs_dir_fetch(clfs, &cwd, clfs->root);
        /*  root的特殊情况   */
        if (err) {
            return err;
        }
    }

    tag = clfs_dir_get(clfs, &cwd, CLFS_MKTAG(0x7ff, 0x3ff, 0),
            CLFS_MKTAG(CLFS_TYPE_USERATTR + type,
                id, clfs_min(size, clfs->attr_max)),
            buffer);
    if (tag < 0) {
        if (tag == CLFS_ERR_NOENT) {
            return CLFS_ERR_NOATTR;
        }

        return tag;
    }

    return clfs_tag_size(tag);
}

#ifndef CLFS_READONLY
static int clfs_commitattr(clfs_t *clfs, const char *path,
        uint8_t type, const void *buffer, clfs_size_t size) {
    clfs_mdir_t cwd;
    clfs_stag_t tag = clfs_dir_find(clfs, &cwd, &path, NULL);
    if (tag < 0) {
        return tag;
    }

    uint16_t id = clfs_tag_id(tag);
    if (id == 0x3ff) {
        id = 0;
        int err = clfs_dir_fetch(clfs, &cwd, clfs->root);
        /*  root的特殊情况   */
        if (err) {
            return err;
        }
    }

    return clfs_dir_commit(clfs, &cwd, CLFS_MKATTRS(
            {CLFS_MKTAG(CLFS_TYPE_USERATTR + type, id, size), buffer}));
}
#endif

#ifndef CLFS_READONLY
static int clfs_rawsetattr(clfs_t *clfs, const char *path,
        uint8_t type, const void *buffer, clfs_size_t size) {
    if (size > clfs->attr_max) {
        return CLFS_ERR_NOSPC;
    }

    return clfs_commitattr(clfs, path, type, buffer, size);
}
#endif

#ifndef CLFS_READONLY
static int clfs_rawremoveattr(clfs_t *clfs, const char *path, uint8_t type) {
    return clfs_commitattr(clfs, path, type, NULL, 0x3ff);
}
#endif

/*********************************************************************************************************
  文件系统操作
*********************************************************************************************************/
// clfs_t文件系统句柄的初始化
static int clfs_init(clfs_t *clfs, const struct clfs_config *cfg) {
    clfs->cfg = cfg;
    int err = 0;

    CLFS_ASSERT(clfs->cfg->read_size != 0);
    /*  验证clfs-cfg大小是否正确初始化   */
    CLFS_ASSERT(clfs->cfg->prog_size != 0);
    CLFS_ASSERT(clfs->cfg->cache_size != 0);


    CLFS_ASSERT(clfs->cfg->cache_size % clfs->cfg->read_size == 0);
    /*  检查缓存大小是读取单位的倍数  */
    CLFS_ASSERT(clfs->cfg->cache_size % clfs->cfg->prog_size == 0);
    /*  检查缓存大小是写入单位的倍数  */
    CLFS_ASSERT(clfs->cfg->block_size % clfs->cfg->cache_size == 0);
    /*  检查块大小是缓存大小的倍数    */


    CLFS_ASSERT(4*clfs_npw2(0xffffffff / (clfs->cfg->block_size-2*4))
    /* 检查块大小是否足够大以适应CTZ指针 */
            <= clfs->cfg->block_size);

    CLFS_ASSERT(clfs->cfg->block_cycles != 0);


    if (clfs->cfg->read_buffer) {
        /* 设置读cache，没有配置则自动malloc */
        clfs->rcache.buffer = clfs->cfg->read_buffer;
    } else {
        clfs->rcache.buffer = clfs_malloc(clfs->cfg->cache_size);
        if (!clfs->rcache.buffer) {
            err = CLFS_ERR_NOMEM;
            goto cleanup;
        }
    }

    if (clfs->cfg->prog_buffer) {
        /* 设置写cache，没有配置则自动malloc */
        clfs->pcache.buffer = clfs->cfg->prog_buffer;
    } else {
        clfs->pcache.buffer = clfs_malloc(clfs->cfg->cache_size);
        if (!clfs->pcache.buffer) {
            err = CLFS_ERR_NOMEM;
            goto cleanup;
        }
    }


    clfs_cache_zero(clfs, &clfs->rcache);
    /* cache设置0以避免信息泄露  */
    clfs_cache_zero(clfs, &clfs->pcache);

    CLFS_ASSERT(clfs->cfg->lookahead_size > 0);
    /* 检查lookafead配置 */
    CLFS_ASSERT(clfs->cfg->lookahead_size % 8 == 0 &&
            (uintptr_t)clfs->cfg->lookahead_buffer % 4 == 0);
    if (clfs->cfg->lookahead_buffer) {
        /* 设置lookahead缓存区，没有配置则自动malloc */
        clfs->free.buffer = clfs->cfg->lookahead_buffer;
    } else {
        clfs->free.buffer = clfs_malloc(clfs->cfg->lookahead_size);
        if (!clfs->free.buffer) {
            err = CLFS_ERR_NOMEM;
            goto cleanup;
        }
    }

    CLFS_ASSERT(clfs->cfg->name_max <= CLFS_NAME_MAX);
    /* 检查大小限制是否正常   */
    clfs->name_max = clfs->cfg->name_max;
    if (!clfs->name_max) {
        clfs->name_max = CLFS_NAME_MAX;
    }

    CLFS_ASSERT(clfs->cfg->file_max <= CLFS_FILE_MAX);
    clfs->file_max = clfs->cfg->file_max;
    if (!clfs->file_max) {
        clfs->file_max = CLFS_FILE_MAX;
    }

    CLFS_ASSERT(clfs->cfg->attr_max <= CLFS_ATTR_MAX);
    clfs->attr_max = clfs->cfg->attr_max;
    if (!clfs->attr_max) {
        clfs->attr_max = CLFS_ATTR_MAX;
    }

    CLFS_ASSERT(clfs->cfg->metadata_max <= clfs->cfg->block_size);

    clfs->root[0] = CLFS_BLOCK_NULL;
    /*   设置默认状态  */
    clfs->root[1] = CLFS_BLOCK_NULL;
    clfs->mlist = NULL;
    clfs->seed = 0;
    clfs->gdisk = (clfs_gstate_t){0};
    clfs->gstate = (clfs_gstate_t){0};
    clfs->gdelta = (clfs_gstate_t){0};
#ifdef CLFS_MIGRATE
    clfs->clfs1 = NULL;
#endif

    return 0;

cleanup:
    clfs_deinit(clfs);
    return err;
}

// clfs_t文件系统句柄取消初始化
static int clfs_deinit(clfs_t *clfs) {
    if (!clfs->cfg->read_buffer) {
        /*  释放已分配的内存   */
        clfs_free(clfs->rcache.buffer);
    }

    if (!clfs->cfg->prog_buffer) {
        clfs_free(clfs->pcache.buffer);
    }

    if (!clfs->cfg->lookahead_buffer) {
        clfs_free(clfs->free.buffer);
    }

    return 0;
}

#ifndef CLFS_READONLY
static int clfs_rawformat(clfs_t *clfs, const struct clfs_config *cfg) {
    int err = 0;
    {
        err = clfs_init(clfs, cfg);
        if (err) {
            return err;
        }

        memset(clfs->free.buffer, 0, clfs->cfg->lookahead_size);
        /* lookahead初始化 */
        clfs->free.off = 0;
        clfs->free.size = clfs_min(8*clfs->cfg->lookahead_size,
                clfs->cfg->block_count);
        clfs->free.i = 0;
        clfs_alloc_ack(clfs);

        clfs_mdir_t root;  /*  创建根目录  */
        err = clfs_dir_alloc(clfs, &root);
        if (err) {
            goto cleanup;
        }

        clfs_superblock_t superblock = {
            /*  写入一个超级块   */
            .version     = CLFS_DISK_VERSION,
            .block_size  = clfs->cfg->block_size,
            .block_count = clfs->cfg->block_count,
            .name_max    = clfs->name_max,
            .file_max    = clfs->file_max,
            .attr_max    = clfs->attr_max,
        };

        clfs_superblock_tole32(&superblock);
        err = clfs_dir_commit(clfs, &root, CLFS_MKATTRS(
                {CLFS_MKTAG(CLFS_TYPE_CREATE, 0, 0), NULL},
                {CLFS_MKTAG(CLFS_TYPE_SUPERBLOCK, 0, 8), "clfs"},
                {CLFS_MKTAG(CLFS_TYPE_INLINESTRUCT, 0, sizeof(superblock)),
                    &superblock}));
        if (err) {
            goto cleanup;
        }

        root.erased = false;
        err = clfs_dir_commit(clfs, &root, NULL, 0);
        /*  强制压缩   */
        if (err) {
            goto cleanup;
        }

        err = clfs_dir_fetch(clfs, &root, (const clfs_block_t[2]){0, 1});
        /*   完整性检查，获取工作  */
        if (err) {
            goto cleanup;
        }
    }

cleanup:
    clfs_deinit(clfs);
    return err;

}
#endif

static int clfs_rawmount(clfs_t *clfs, const struct clfs_config *cfg) {
    int err = clfs_init(clfs, cfg);
    if (err) {
        return err;
    }

    clfs_mdir_t dir = {.tail = {0, 1}};
    /*  扫描目录块的超级块和任何全局更新   */
    clfs_block_t cycle = 0;
    while (!clfs_pair_isnull(dir.tail)) {
        if (cycle >= clfs->cfg->block_count/2) {
            /*  发现环路   */
            err = CLFS_ERR_CORRUPT;
            goto cleanup;
        }
        cycle += 1;

        clfs_stag_t tag = clfs_dir_fetchmatch(clfs, &dir, dir.tail,
        /*  在尾列表中获取下一个块   */
                CLFS_MKTAG(0x7ff, 0x3ff, 0),
                CLFS_MKTAG(CLFS_TYPE_SUPERBLOCK, 0, 8),
                NULL,
                clfs_dir_find_match, &(struct clfs_dir_find_match){
                    clfs, "clfs", 8});
        if (tag < 0) {
            err = tag;
            goto cleanup;
        }


        if (tag && !clfs_tag_isdelete(tag)) {
            /*  是否是超级块   */
            // update root
            clfs->root[0] = dir.pair[0];
            clfs->root[1] = dir.pair[1];

            clfs_superblock_t superblock;
            /*   获取超级块  */
            tag = clfs_dir_get(clfs, &dir, CLFS_MKTAG(0x7ff, 0x3ff, 0),
                    CLFS_MKTAG(CLFS_TYPE_INLINESTRUCT, 0, sizeof(superblock)),
                    &superblock);
            if (tag < 0) {
                err = tag;
                goto cleanup;
            }
            clfs_superblock_fromle32(&superblock);

            uint16_t major_version = (0xffff & (superblock.version >> 16));
            /*  检查版本   */
            uint16_t minor_version = (0xffff & (superblock.version >>  0));
            if ((major_version != CLFS_DISK_VERSION_MAJOR ||
                 minor_version > CLFS_DISK_VERSION_MINOR)) {
                CLFS_ERROR("Invalid version v%"PRIu16".%"PRIu16,
                        major_version, minor_version);
                err = CLFS_ERR_INVAL;
                goto cleanup;
            }

            if (superblock.name_max) {
                /*  检查超级块配置   */
                if (superblock.name_max > clfs->name_max) {
                    CLFS_ERROR("Unsupported name_max (%"PRIu32" > %"PRIu32")",
                            superblock.name_max, clfs->name_max);
                    err = CLFS_ERR_INVAL;
                    goto cleanup;
                }

                clfs->name_max = superblock.name_max;
            }

            if (superblock.file_max) {
                if (superblock.file_max > clfs->file_max) {
                    CLFS_ERROR("Unsupported file_max (%"PRIu32" > %"PRIu32")",
                            superblock.file_max, clfs->file_max);
                    err = CLFS_ERR_INVAL;
                    goto cleanup;
                }

                clfs->file_max = superblock.file_max;
            }

            if (superblock.attr_max) {
                if (superblock.attr_max > clfs->attr_max) {
                    CLFS_ERROR("Unsupported attr_max (%"PRIu32" > %"PRIu32")",
                            superblock.attr_max, clfs->attr_max);
                    err = CLFS_ERR_INVAL;
                    goto cleanup;
                }

                clfs->attr_max = superblock.attr_max;
            }

            if (superblock.block_count != clfs->cfg->block_count) {
                CLFS_ERROR("Invalid block count (%"PRIu32" != %"PRIu32")",
                        superblock.block_count, clfs->cfg->block_count);
                err = CLFS_ERR_INVAL;
                goto cleanup;
            }

            if (superblock.block_size != clfs->cfg->block_size) {
                CLFS_ERROR("Invalid block size (%"PRIu32" != %"PRIu32")",
                        superblock.block_count, clfs->cfg->block_count);
                err = CLFS_ERR_INVAL;
                goto cleanup;
            }
        }


        err = clfs_dir_getgstate(clfs, &dir, &clfs->gstate);
        /*  是否有gstate   */
        if (err) {
            goto cleanup;
        }
    }

    if (clfs_pair_isnull(clfs->root)) {
        /*  是否找到超块   */
        err = CLFS_ERR_INVAL;
        goto cleanup;
    }

    if (!clfs_gstate_iszero(&clfs->gstate)) {
        /*  用gstate更新文件系统   */
        CLFS_DEBUG("Found pending gstate 0x%08"PRIx32"%08"PRIx32"%08"PRIx32,
                clfs->gstate.tag,
                clfs->gstate.pair[0],
                clfs->gstate.pair[1]);
    }
    clfs->gstate.tag += !clfs_tag_isvalid(clfs->gstate.tag);
    clfs->gdisk = clfs->gstate;

    clfs->free.off = clfs->seed % clfs->cfg->block_count;
    /*  随机位置启动分配器   */
    clfs_alloc_drop(clfs);

    return 0;

cleanup:
    clfs_rawunmount(clfs);
    return err;
}

static int clfs_rawunmount(clfs_t *clfs) {
    return clfs_deinit(clfs);
}

/*********************************************************************************************************
      Filesystem文件系统操作
*********************************************************************************************************/
int clfs_fs_rawtraverse(clfs_t *clfs,
        int (*cb)(void *data, clfs_block_t block), void *data,
        bool includeorphans) {

    clfs_mdir_t dir = {.tail = {0, 1}};
    /*  迭代元数据对   */

    clfs_block_t cycle = 0;
    while (!clfs_pair_isnull(dir.tail)) {
        if (cycle >= clfs->cfg->block_count/2) {
            /*  发现环路   */
            return CLFS_ERR_CORRUPT;
        }
        cycle += 1;
        int i;
        for (i = 0; i < 2; i++) {
            int err = cb(data, dir.tail[i]);
            if (err) {
                return err;
            }
        }


        int err = clfs_dir_fetch(clfs, &dir, dir.tail);
        /*  迭代目录中的id   */
        if (err) {
            return err;
        }
        uint16_t id ;
        for (id = 0; id < dir.count; id++) {
            struct clfs_ctz ctz;
            clfs_stag_t tag = clfs_dir_get(clfs, &dir, CLFS_MKTAG(0x700, 0x3ff, 0),
                    CLFS_MKTAG(CLFS_TYPE_STRUCT, id, sizeof(ctz)), &ctz);
            if (tag < 0) {
                if (tag == CLFS_ERR_NOENT) {
                    continue;
                }
                return tag;
            }
            clfs_ctz_fromle32(&ctz);

            if (clfs_tag_type3(tag) == CLFS_TYPE_CTZSTRUCT) {
                err = clfs_ctz_traverse(clfs, NULL, &clfs->rcache,
                        ctz.head, ctz.size, cb, data);
                if (err) {
                    return err;
                }
            } else if (includeorphans &&
                    clfs_tag_type3(tag) == CLFS_TYPE_DIRSTRUCT) {
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

#ifndef CLFS_READONLY
    clfs_file_t *f;
    for (f = (clfs_file_t*)clfs->mlist; f; f = f->next) {
        /*  迭代任何打开的文件   */
        if (f->type != CLFS_TYPE_REG) {
            continue;
        }

        if ((f->flags & CLFS_F_DIRTY) && !(f->flags & CLFS_F_INLINE)) {
            int err = clfs_ctz_traverse(clfs, &f->cache, &clfs->rcache,
                    f->ctz.head, f->ctz.size, cb, data);
            if (err) {
                return err;
            }
        }

        if ((f->flags & CLFS_F_WRITING) && !(f->flags & CLFS_F_INLINE)) {
            int err = clfs_ctz_traverse(clfs, &f->cache, &clfs->rcache,
                    f->block, f->pos, cb, data);
            if (err) {
                return err;
            }
        }
    }
#endif

    return 0;
}

#ifndef CLFS_READONLY
static int clfs_fs_pred(clfs_t *clfs,
        const clfs_block_t pair[2], clfs_mdir_t *pdir) {
            /*  迭代所有目录的目录条目   */
    pdir->tail[0] = 0;
    pdir->tail[1] = 1;
    clfs_block_t cycle = 0;
    while (!clfs_pair_isnull(pdir->tail)) {
        if (cycle >= clfs->cfg->block_count/2) {
            /*  发现环路   */
            return CLFS_ERR_CORRUPT;
        }
        cycle += 1;

        if (clfs_pair_cmp(pdir->tail, pair) == 0) {
            return 0;
        }

        int err = clfs_dir_fetch(clfs, pdir, pdir->tail);
        if (err) {
            return err;
        }
    }

    return CLFS_ERR_NOENT;
}
#endif

#ifndef CLFS_READONLY
struct clfs_fs_parent_match {
    clfs_t *clfs;
    const clfs_block_t pair[2];
};
#endif

#ifndef CLFS_READONLY
static int clfs_fs_parent_match(void *data,
        clfs_tag_t tag, const void *buffer) {
    struct clfs_fs_parent_match *find = data;
    clfs_t *clfs = find->clfs;
    const struct clfs_diskoff *disk = buffer;
    (void)tag;

    clfs_block_t child[2];
    int err = clfs_bd_read(clfs,
            &clfs->pcache, &clfs->rcache, clfs->cfg->block_size,
            disk->block, disk->off, &child, sizeof(child));
    if (err) {
        return err;
    }

    clfs_pair_fromle32(child);
    return (clfs_pair_cmp(child, find->pair) == 0) ? CLFS_CMP_EQ : CLFS_CMP_LT;
}
#endif

#ifndef CLFS_READONLY
static clfs_stag_t clfs_fs_parent(clfs_t *clfs, const clfs_block_t pair[2],
        clfs_mdir_t *parent) {
    parent->tail[0] = 0;
    /*  使用fetchmatch和callback来查找配对    */
    parent->tail[1] = 1;
    clfs_block_t cycle = 0;
    while (!clfs_pair_isnull(parent->tail)) {
        if (cycle >= clfs->cfg->block_count/2) {
            /*  发现环路   */

            return CLFS_ERR_CORRUPT;
        }
        cycle += 1;

        clfs_stag_t tag = clfs_dir_fetchmatch(clfs, parent, parent->tail,
                CLFS_MKTAG(0x7ff, 0, 0x3ff),
                CLFS_MKTAG(CLFS_TYPE_DIRSTRUCT, 0, 8),
                NULL,
                clfs_fs_parent_match, &(struct clfs_fs_parent_match){
                    clfs, {pair[0], pair[1]}});
        if (tag && tag != CLFS_ERR_NOENT) {
            return tag;
        }
    }

    return CLFS_ERR_NOENT;
}
#endif

#ifndef CLFS_READONLY
static int clfs_fs_preporphans(clfs_t *clfs, int8_t orphans) {
    CLFS_ASSERT(clfs_tag_size(clfs->gstate.tag) > 0 || orphans >= 0);
    clfs->gstate.tag += orphans;
    clfs->gstate.tag = ((clfs->gstate.tag & ~CLFS_MKTAG(0x800, 0, 0)) |
            ((uint32_t)clfs_gstate_hasorphans(&clfs->gstate) << 31));

    return 0;
}
#endif

#ifndef CLFS_READONLY
static void clfs_fs_prepmove(clfs_t *clfs,
        uint16_t id, const clfs_block_t pair[2]) {
    clfs->gstate.tag = ((clfs->gstate.tag & ~CLFS_MKTAG(0x7ff, 0x3ff, 0)) |
            ((id != 0x3ff) ? CLFS_MKTAG(CLFS_TYPE_DELETE, id, 0) : 0));
    clfs->gstate.pair[0] = (id != 0x3ff) ? pair[0] : 0;
    clfs->gstate.pair[1] = (id != 0x3ff) ? pair[1] : 0;
}
#endif

#ifndef CLFS_READONLY
static int clfs_fs_demove(clfs_t *clfs) {
    if (!clfs_gstate_hasmove(&clfs->gdisk)) {
        return 0;
    }


    CLFS_DEBUG("Fixing move {0x%"PRIx32", 0x%"PRIx32"} 0x%"PRIx16,
            /*   修正错误的操作  */
            clfs->gdisk.pair[0],
            clfs->gdisk.pair[1],
            clfs_tag_id(clfs->gdisk.tag));


    clfs_mdir_t movedir;
    int err = clfs_dir_fetch(clfs, &movedir, clfs->gdisk.pair);
    /*  获取并删除被移动的条目   */
    if (err) {
        return err;
    }

    uint16_t moveid = clfs_tag_id(clfs->gdisk.tag);
    /*  准备gstate并删除moveid   */
    clfs_fs_prepmove(clfs, 0x3ff, NULL);
    err = clfs_dir_commit(clfs, &movedir, CLFS_MKATTRS(
            {CLFS_MKTAG(CLFS_TYPE_DELETE, moveid, 0), NULL}));
    if (err) {
        return err;
    }

    return 0;
}
#endif

#ifndef CLFS_READONLY
static int clfs_fs_deorphan(clfs_t *clfs, bool powerloss) {
    if (!clfs_gstate_hasorphans(&clfs->gstate)) {
        return 0;
    }

    int8_t found = 0;
restart:
    {
        clfs_mdir_t pdir = {.split = true, .tail = {0, 1}};
        /*  修复孤儿   */
        clfs_mdir_t dir;


        while (!clfs_pair_isnull(pdir.tail)) {
            /* 迭代所有目录的目录条目  */
            int err = clfs_dir_fetch(clfs, &dir, pdir.tail);
            if (err) {
                return err;
            }

            if (!pdir.split) {
                /*  检查孤儿头部块   */

                clfs_mdir_t parent;
                clfs_stag_t tag = clfs_fs_parent(clfs, pdir.tail, &parent);
                /*  检查是否有父母   */
                if (tag < 0 && tag != CLFS_ERR_NOENT) {
                    return tag;
                }

                if (tag == CLFS_ERR_NOENT && powerloss) {
                    /*  孤儿   */

                    CLFS_DEBUG("Fixing orphan {0x%"PRIx32", 0x%"PRIx32"}",
                            pdir.tail[0], pdir.tail[1]);


                    err = clfs_dir_getgstate(clfs, &dir, &clfs->gdelta);
                    /*  三态控制   */
                    if (err) {
                        return err;
                    }

                    clfs_pair_tole32(dir.tail);
                    int state = clfs_dir_orphaningcommit(clfs, &pdir, CLFS_MKATTRS(
                            {CLFS_MKTAG(CLFS_TYPE_TAIL + dir.split, 0x3ff, 8),
                                dir.tail}));
                    clfs_pair_fromle32(dir.tail);
                    if (state < 0) {
                        return state;
                    }

                    found += 1;

                    if (state == CLFS_OK_ORPHANED) {
                        /*  是否创造了更多的孤儿   */
                        goto restart;
                    }

                    continue;
                    /*  重新取回尾部   */
                }

                if (tag != CLFS_ERR_NOENT) {
                    clfs_block_t pair[2];
                    clfs_stag_t state = clfs_dir_get(clfs, &parent,
                            CLFS_MKTAG(0x7ff, 0x3ff, 0), tag, pair);
                    if (state < 0) {
                        return state;
                    }
                    clfs_pair_fromle32(pair);

                    if (!clfs_pair_sync(pair, pdir.tail)) {
                        /*  已经同步   */

                        CLFS_DEBUG("Fixing half-orphan "
                                "{0x%"PRIx32", 0x%"PRIx32"} "
                                "-> {0x%"PRIx32", 0x%"PRIx32"}",
                                pdir.tail[0], pdir.tail[1], pair[0], pair[1]);


                        uint16_t moveid = 0x3ff;
                        if (clfs_gstate_hasmovehere(&clfs->gstate, pdir.pair)) {
                            moveid = clfs_tag_id(clfs->gstate.tag);
                            CLFS_DEBUG("Fixing move while fixing orphans "
                                    "{0x%"PRIx32", 0x%"PRIx32"} 0x%"PRIx16"\n",
                                    pdir.pair[0], pdir.pair[1], moveid);
                            clfs_fs_prepmove(clfs, 0x3ff, NULL);
                        }

                        clfs_pair_tole32(pair);
                        state = clfs_dir_orphaningcommit(clfs, &pdir, CLFS_MKATTRS(
                                {CLFS_MKTAG_IF(moveid != 0x3ff,
                                    CLFS_TYPE_DELETE, moveid, 0), NULL},
                                {CLFS_MKTAG(CLFS_TYPE_SOFTTAIL, 0x3ff, 8),
                                    pair}));
                        clfs_pair_fromle32(pair);
                        if (state < 0) {
                            return state;
                        }

                        found += 1;


                        if (state == CLFS_OK_ORPHANED) {
                            /*   是否创造了更多的孤儿  */
                            goto restart;
                        }
                        /* 重新取回尾部    */
                        continue;
                    }
                }
            }

            pdir = dir;
        }
    }


    return clfs_fs_preporphans(clfs, -clfs_min(
        /*  将孤儿标记为固定的   */
            clfs_gstate_getorphans(&clfs->gstate),
            found));
}
#endif

#ifndef CLFS_READONLY
static int clfs_fs_forceconsistency(clfs_t *clfs) {
    int err = clfs_fs_demove(clfs);
    if (err) {
        return err;
    }

    err = clfs_fs_deorphan(clfs, true);
    if (err) {
        return err;
    }

    return 0;
}
#endif

static int clfs_fs_size_count(void *p, clfs_block_t block) {
    (void)block;
    clfs_size_t *size = p;
    *size += 1;
    return 0;
}

static clfs_ssize_t clfs_fs_rawsize(clfs_t *clfs) {
    clfs_size_t size = 0;
    int err = clfs_fs_rawtraverse(clfs, clfs_fs_size_count, &size, false);
    if (err) {
        return err;
    }

    return size;
}


/*********************************************************************************************************
  开放函数API /如果启用线程安全的包装器
*********************************************************************************************************/

// 线程安全的包装器
#ifdef CLFS_THREADSAFE
#define CLFS_LOCK(cfg)   cfg->lock(cfg)
#define CLFS_UNLOCK(cfg) cfg->unlock(cfg)
#else
#define CLFS_LOCK(cfg)   ((void)cfg, 0)
#define CLFS_UNLOCK(cfg) ((void)cfg)
#endif

#ifndef CLFS_READONLY
int clfs_format(clfs_t *clfs, const struct clfs_config *cfg) {
    int err = CLFS_LOCK(cfg);
    if (err) {
        return err;
    }
    CLFS_TRACE("clfs_format(%p, %p {.context=%p, "
                ".read=%p, .prog=%p, .erase=%p, .sync=%p, "
                ".read_size=%"PRIu32", .prog_size=%"PRIu32", "
                ".block_size=%"PRIu32", .block_count=%"PRIu32", "
                ".block_cycles=%"PRIu32", .cache_size=%"PRIu32", "
                ".lookahead_size=%"PRIu32", .read_buffer=%p, "
                ".prog_buffer=%p, .lookahead_buffer=%p, "
                ".name_max=%"PRIu32", .file_max=%"PRIu32", "
                ".attr_max=%"PRIu32"})",
            (void*)clfs, (void*)cfg, cfg->context,
            (void*)(uintptr_t)cfg->read, (void*)(uintptr_t)cfg->prog,
            (void*)(uintptr_t)cfg->erase, (void*)(uintptr_t)cfg->sync,
            cfg->read_size, cfg->prog_size, cfg->block_size, cfg->block_count,
            cfg->block_cycles, cfg->cache_size, cfg->lookahead_size,
            cfg->read_buffer, cfg->prog_buffer, cfg->lookahead_buffer,
            cfg->name_max, cfg->file_max, cfg->attr_max);

    err = clfs_rawformat(clfs, cfg);

    CLFS_TRACE("clfs_format -> %d", err);
    CLFS_UNLOCK(cfg);
    return err;
}
#endif

int clfs_mount(clfs_t *clfs, const struct clfs_config *cfg) {
    int err = CLFS_LOCK(cfg);
    if (err) {
        return err;
    }
    CLFS_TRACE("clfs_mount(%p, %p {.context=%p, "
                ".read=%p, .prog=%p, .erase=%p, .sync=%p, "
                ".read_size=%"PRIu32", .prog_size=%"PRIu32", "
                ".block_size=%"PRIu32", .block_count=%"PRIu32", "
                ".block_cycles=%"PRIu32", .cache_size=%"PRIu32", "
                ".lookahead_size=%"PRIu32", .read_buffer=%p, "
                ".prog_buffer=%p, .lookahead_buffer=%p, "
                ".name_max=%"PRIu32", .file_max=%"PRIu32", "
                ".attr_max=%"PRIu32"})",
            (void*)clfs, (void*)cfg, cfg->context,
            (void*)(uintptr_t)cfg->read, (void*)(uintptr_t)cfg->prog,
            (void*)(uintptr_t)cfg->erase, (void*)(uintptr_t)cfg->sync,
            cfg->read_size, cfg->prog_size, cfg->block_size, cfg->block_count,
            cfg->block_cycles, cfg->cache_size, cfg->lookahead_size,
            cfg->read_buffer, cfg->prog_buffer, cfg->lookahead_buffer,
            cfg->name_max, cfg->file_max, cfg->attr_max);

    err = clfs_rawmount(clfs, cfg);
    CLFS_TRACE("clfs_mount -> %d", err);
    CLFS_UNLOCK(cfg);
    return err;
}

int clfs_unmount(clfs_t *clfs) {
    int err = CLFS_LOCK(clfs->cfg);
    if (err) {
        return err;
    }
    CLFS_TRACE("clfs_unmount(%p)", (void*)clfs);

    err = clfs_rawunmount(clfs);

    CLFS_TRACE("clfs_unmount -> %d", err);
    CLFS_UNLOCK(clfs->cfg);
    return err;
}

#ifndef CLFS_READONLY
int clfs_remove(clfs_t *clfs, const char *path) {
    int err = CLFS_LOCK(clfs->cfg);
    if (err) {
        return err;
    }
    CLFS_TRACE("clfs_remove(%p, \"%s\")", (void*)clfs, path);

    err = clfs_rawremove(clfs, path);

    CLFS_TRACE("clfs_remove -> %d", err);
    CLFS_UNLOCK(clfs->cfg);
    return err;
}
#endif

#ifndef CLFS_READONLY
int clfs_rename(clfs_t *clfs, const char *oldpath, const char *newpath) {
    int err = CLFS_LOCK(clfs->cfg);
    if (err) {
        return err;
    }
    CLFS_TRACE("clfs_rename(%p, \"%s\", \"%s\")", (void*)clfs, oldpath, newpath);

    err = clfs_rawrename(clfs, oldpath, newpath);

    CLFS_TRACE("clfs_rename -> %d", err);
    CLFS_UNLOCK(clfs->cfg);
    return err;
}
#endif

int clfs_stat(clfs_t *clfs, const char *path, struct clfs_info *info) {
    int err = CLFS_LOCK(clfs->cfg);
    if (err) {
        return err;
    }
    CLFS_TRACE("clfs_stat(%p, \"%s\", %p)", (void*)clfs, path, (void*)info);

    err = clfs_rawstat(clfs, path, info);

    CLFS_TRACE("clfs_stat -> %d", err);
    CLFS_UNLOCK(clfs->cfg);
    return err;
}

clfs_ssize_t clfs_getattr(clfs_t *clfs, const char *path,
        uint8_t type, void *buffer, clfs_size_t size) {
    int err = CLFS_LOCK(clfs->cfg);
    if (err) {
        return err;
    }
    CLFS_TRACE("clfs_getattr(%p, \"%s\", %"PRIu8", %p, %"PRIu32")",
            (void*)clfs, path, type, buffer, size);

    clfs_ssize_t res = clfs_rawgetattr(clfs, path, type, buffer, size);

    CLFS_TRACE("clfs_getattr -> %"PRId32, res);
    CLFS_UNLOCK(clfs->cfg);
    return res;
}

#ifndef CLFS_READONLY
int clfs_setattr(clfs_t *clfs, const char *path,
        uint8_t type, const void *buffer, clfs_size_t size) {
    int err = CLFS_LOCK(clfs->cfg);
    if (err) {
        return err;
    }
    CLFS_TRACE("clfs_setattr(%p, \"%s\", %"PRIu8", %p, %"PRIu32")",
            (void*)clfs, path, type, buffer, size);

    err = clfs_rawsetattr(clfs, path, type, buffer, size);

    CLFS_TRACE("clfs_setattr -> %d", err);
    CLFS_UNLOCK(clfs->cfg);
    return err;
}
#endif

#ifndef CLFS_READONLY
int clfs_removeattr(clfs_t *clfs, const char *path, uint8_t type) {
    int err = CLFS_LOCK(clfs->cfg);
    if (err) {
        return err;
    }
    CLFS_TRACE("clfs_removeattr(%p, \"%s\", %"PRIu8")", (void*)clfs, path, type);

    err = clfs_rawremoveattr(clfs, path, type);

    CLFS_TRACE("clfs_removeattr -> %d", err);
    CLFS_UNLOCK(clfs->cfg);
    return err;
}
#endif

#ifndef CLFS_NO_MALLOC
int clfs_file_open(clfs_t *clfs, clfs_file_t *file, const char *path, int flags) {
    int err = CLFS_LOCK(clfs->cfg);
    if (err) {
        return err;
    }
    CLFS_TRACE("clfs_file_open(%p, %p, \"%s\", %x)",
            (void*)clfs, (void*)file, path, flags);
    CLFS_ASSERT(!clfs_mlist_isopen(clfs->mlist, (struct clfs_mlist*)file));

    err = clfs_file_rawopen(clfs, file, path, flags);

    CLFS_TRACE("clfs_file_open -> %d", err);
    CLFS_UNLOCK(clfs->cfg);
    return err;
}
#endif

int clfs_file_opencfg(clfs_t *clfs, clfs_file_t *file,
        const char *path, int flags,
        const struct clfs_file_config *cfg) {
    int err = CLFS_LOCK(clfs->cfg);
    if (err) {
        return err;
    }
    CLFS_TRACE("clfs_file_opencfg(%p, %p, \"%s\", %x, %p {"
                 ".buffer=%p, .attrs=%p, .attr_count=%"PRIu32"})",
            (void*)clfs, (void*)file, path, flags,
            (void*)cfg, cfg->buffer, (void*)cfg->attrs, cfg->attr_count);
    CLFS_ASSERT(!clfs_mlist_isopen(clfs->mlist, (struct clfs_mlist*)file));

    err = clfs_file_rawopencfg(clfs, file, path, flags, cfg);

    CLFS_TRACE("clfs_file_opencfg -> %d", err);
    CLFS_UNLOCK(clfs->cfg);
    return err;
}

int clfs_file_close(clfs_t *clfs, clfs_file_t *file) {
    int err = CLFS_LOCK(clfs->cfg);
    if (err) {
        return err;
    }
    CLFS_TRACE("clfs_file_close(%p, %p)", (void*)clfs, (void*)file);
    CLFS_ASSERT(clfs_mlist_isopen(clfs->mlist, (struct clfs_mlist*)file));

    err = clfs_file_rawclose(clfs, file);

    CLFS_TRACE("clfs_file_close -> %d", err);
    CLFS_UNLOCK(clfs->cfg);
    return err;
}

#ifndef CLFS_READONLY
int clfs_file_sync(clfs_t *clfs, clfs_file_t *file) {
    int err = CLFS_LOCK(clfs->cfg);
    if (err) {
        return err;
    }
    CLFS_TRACE("clfs_file_sync(%p, %p)", (void*)clfs, (void*)file);
    CLFS_ASSERT(clfs_mlist_isopen(clfs->mlist, (struct clfs_mlist*)file));

    err = clfs_file_rawsync(clfs, file);

    CLFS_TRACE("clfs_file_sync -> %d", err);
    CLFS_UNLOCK(clfs->cfg);
    return err;
}
#endif

clfs_ssize_t clfs_file_read(clfs_t *clfs, clfs_file_t *file,
        void *buffer, clfs_size_t size) {
    int err = CLFS_LOCK(clfs->cfg);
    if (err) {
        return err;
    }
    CLFS_TRACE("clfs_file_read(%p, %p, %p, %"PRIu32")",
            (void*)clfs, (void*)file, buffer, size);
    CLFS_ASSERT(clfs_mlist_isopen(clfs->mlist, (struct clfs_mlist*)file));

    clfs_ssize_t res = clfs_file_rawread(clfs, file, buffer, size);

    CLFS_TRACE("clfs_file_read -> %"PRId32, res);
    CLFS_UNLOCK(clfs->cfg);
    return res;
}

#ifndef CLFS_READONLY
clfs_ssize_t clfs_file_write(clfs_t *clfs, clfs_file_t *file,
        const void *buffer, clfs_size_t size) {
    int err = CLFS_LOCK(clfs->cfg);
    if (err) {
        return err;
    }
    CLFS_TRACE("clfs_file_write(%p, %p, %p, %"PRIu32")",
            (void*)clfs, (void*)file, buffer, size);
    CLFS_ASSERT(clfs_mlist_isopen(clfs->mlist, (struct clfs_mlist*)file));

    clfs_ssize_t res = clfs_file_rawwrite(clfs, file, buffer, size);

    CLFS_TRACE("clfs_file_write -> %"PRId32, res);
    CLFS_UNLOCK(clfs->cfg);
    return res;
}
#endif

clfs_soff_t clfs_file_seek(clfs_t *clfs, clfs_file_t *file,
        clfs_soff_t off, int whence) {
    int err = CLFS_LOCK(clfs->cfg);
    if (err) {
        return err;
    }
    CLFS_TRACE("clfs_file_seek(%p, %p, %"PRId32", %d)",
            (void*)clfs, (void*)file, off, whence);
    CLFS_ASSERT(clfs_mlist_isopen(clfs->mlist, (struct clfs_mlist*)file));

    clfs_soff_t res = clfs_file_rawseek(clfs, file, off, whence);

    CLFS_TRACE("clfs_file_seek -> %"PRId32, res);
    CLFS_UNLOCK(clfs->cfg);
    return res;
}

#ifndef CLFS_READONLY
int clfs_file_truncate(clfs_t *clfs, clfs_file_t *file, clfs_off_t size) {
    int err = CLFS_LOCK(clfs->cfg);
    if (err) {
        return err;
    }
    CLFS_TRACE("clfs_file_truncate(%p, %p, %"PRIu32")",
            (void*)clfs, (void*)file, size);
    CLFS_ASSERT(clfs_mlist_isopen(clfs->mlist, (struct clfs_mlist*)file));

    err = clfs_file_rawtruncate(clfs, file, size);

    CLFS_TRACE("clfs_file_truncate -> %d", err);
    CLFS_UNLOCK(clfs->cfg);
    return err;
}
#endif

clfs_soff_t clfs_file_tell(clfs_t *clfs, clfs_file_t *file) {
    int err = CLFS_LOCK(clfs->cfg);
    if (err) {
        return err;
    }
    CLFS_TRACE("clfs_file_tell(%p, %p)", (void*)clfs, (void*)file);
    CLFS_ASSERT(clfs_mlist_isopen(clfs->mlist, (struct clfs_mlist*)file));

    clfs_soff_t res = clfs_file_rawtell(clfs, file);

    CLFS_TRACE("clfs_file_tell -> %"PRId32, res);
    CLFS_UNLOCK(clfs->cfg);
    return res;
}

int clfs_file_rewind(clfs_t *clfs, clfs_file_t *file) {
    int err = CLFS_LOCK(clfs->cfg);
    if (err) {
        return err;
    }
    CLFS_TRACE("clfs_file_rewind(%p, %p)", (void*)clfs, (void*)file);

    err = clfs_file_rawrewind(clfs, file);

    CLFS_TRACE("clfs_file_rewind -> %d", err);
    CLFS_UNLOCK(clfs->cfg);
    return err;
}

clfs_soff_t clfs_file_size(clfs_t *clfs, clfs_file_t *file) {
    int err = CLFS_LOCK(clfs->cfg);
    if (err) {
        return err;
    }
    CLFS_TRACE("clfs_file_size(%p, %p)", (void*)clfs, (void*)file);
    CLFS_ASSERT(clfs_mlist_isopen(clfs->mlist, (struct clfs_mlist*)file));

    clfs_soff_t res = clfs_file_rawsize(clfs, file);

    CLFS_TRACE("clfs_file_size -> %"PRId32, res);
    CLFS_UNLOCK(clfs->cfg);
    return res;
}

#ifndef CLFS_READONLY
int clfs_mkdir(clfs_t *clfs, const char *path) {
    int err = CLFS_LOCK(clfs->cfg);
    if (err) {
        return err;
    }
    CLFS_TRACE("clfs_mkdir(%p, \"%s\")", (void*)clfs, path);

    err = clfs_rawmkdir(clfs, path);

    CLFS_TRACE("clfs_mkdir -> %d", err);
    CLFS_UNLOCK(clfs->cfg);
    return err;
}
#endif

int clfs_dir_open(clfs_t *clfs, clfs_dir_t *dir, const char *path) {
    int err = CLFS_LOCK(clfs->cfg);
    if (err) {
        return err;
    }
    CLFS_TRACE("clfs_dir_open(%p, %p, \"%s\")", (void*)clfs, (void*)dir, path);
    CLFS_ASSERT(!clfs_mlist_isopen(clfs->mlist, (struct clfs_mlist*)dir));

    err = clfs_dir_rawopen(clfs, dir, path);

    CLFS_TRACE("clfs_dir_open -> %d", err);
    CLFS_UNLOCK(clfs->cfg);
    return err;
}

int clfs_dir_close(clfs_t *clfs, clfs_dir_t *dir) {
    int err = CLFS_LOCK(clfs->cfg);
    if (err) {
        return err;
    }
    CLFS_TRACE("clfs_dir_close(%p, %p)", (void*)clfs, (void*)dir);

    err = clfs_dir_rawclose(clfs, dir);

    CLFS_TRACE("clfs_dir_close -> %d", err);
    CLFS_UNLOCK(clfs->cfg);
    return err;
}

int clfs_dir_read(clfs_t *clfs, clfs_dir_t *dir, struct clfs_info *info) {
    int err = CLFS_LOCK(clfs->cfg);
    if (err) {
        return err;
    }
    CLFS_TRACE("clfs_dir_read(%p, %p, %p)",
            (void*)clfs, (void*)dir, (void*)info);

    err = clfs_dir_rawread(clfs, dir, info);

    CLFS_TRACE("clfs_dir_read -> %d", err);
    CLFS_UNLOCK(clfs->cfg);
    return err;
}

int clfs_dir_seek(clfs_t *clfs, clfs_dir_t *dir, clfs_off_t off) {
    int err = CLFS_LOCK(clfs->cfg);
    if (err) {
        return err;
    }
    CLFS_TRACE("clfs_dir_seek(%p, %p, %"PRIu32")",
            (void*)clfs, (void*)dir, off);

    err = clfs_dir_rawseek(clfs, dir, off);

    CLFS_TRACE("clfs_dir_seek -> %d", err);
    CLFS_UNLOCK(clfs->cfg);
    return err;
}

clfs_soff_t clfs_dir_tell(clfs_t *clfs, clfs_dir_t *dir) {
    int err = CLFS_LOCK(clfs->cfg);
    if (err) {
        return err;
    }
    CLFS_TRACE("clfs_dir_tell(%p, %p)", (void*)clfs, (void*)dir);

    clfs_soff_t res = clfs_dir_rawtell(clfs, dir);

    CLFS_TRACE("clfs_dir_tell -> %"PRId32, res);
    CLFS_UNLOCK(clfs->cfg);
    return res;
}

int clfs_dir_rewind(clfs_t *clfs, clfs_dir_t *dir) {
    int err = CLFS_LOCK(clfs->cfg);
    if (err) {
        return err;
    }
    CLFS_TRACE("clfs_dir_rewind(%p, %p)", (void*)clfs, (void*)dir);

    err = clfs_dir_rawrewind(clfs, dir);

    CLFS_TRACE("clfs_dir_rewind -> %d", err);
    CLFS_UNLOCK(clfs->cfg);
    return err;
}

clfs_ssize_t clfs_fs_size(clfs_t *clfs) {
    int err = CLFS_LOCK(clfs->cfg);
    if (err) {
        return err;
    }
    CLFS_TRACE("clfs_fs_size(%p)", (void*)clfs);

    clfs_ssize_t res = clfs_fs_rawsize(clfs);

    CLFS_TRACE("clfs_fs_size -> %"PRId32, res);
    CLFS_UNLOCK(clfs->cfg);
    return res;
}

int clfs_fs_traverse(clfs_t *clfs, int (*cb)(void *, clfs_block_t), void *data) {
    int err = CLFS_LOCK(clfs->cfg);
    if (err) {
        return err;
    }
    CLFS_TRACE("clfs_fs_traverse(%p, %p, %p)",
            (void*)clfs, (void*)(uintptr_t)cb, data);

    err = clfs_fs_rawtraverse(clfs, cb, data, true);

    CLFS_TRACE("clfs_fs_traverse -> %d", err);
    CLFS_UNLOCK(clfs->cfg);
    return err;
}
