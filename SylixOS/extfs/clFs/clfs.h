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
** 文   件   名: clfs.h
**
** 创   建   人: 章俊文
**
** 文件创建日期: 2022 年 06 月 04 日
**
** 描        述: clfs相关工具包的h文件
*********************************************************************************************************/
#ifndef CLFS_H
#define CLFS_H

#include <stdint.h>
#include <stdbool.h>
#include "clfs_util.h"

#ifdef __cplusplus
extern "C"
{
#endif


/*********************************************************************************************************
  版本信息
*********************************************************************************************************/

/* 说明：软件库版本 */
#define CLFS_VERSION 0x00020005
#define CLFS_VERSION_MAJOR (0xffff & (CLFS_VERSION >> 16))
#define CLFS_VERSION_MINOR (0xffff & (CLFS_VERSION >>  0))

/* 说明：磁盘上数据结构的版本 */
#define CLFS_DISK_VERSION 0x00020000
#define CLFS_DISK_VERSION_MAJOR (0xffff & (CLFS_DISK_VERSION >> 16))
#define CLFS_DISK_VERSION_MINOR (0xffff & (CLFS_DISK_VERSION >>  0))

/*********************************************************************************************************
  内部常量
*********************************************************************************************************/
/* 说明：类型定义 */
typedef uint32_t clfs_size_t;
typedef uint32_t clfs_off_t;

typedef int32_t  clfs_ssize_t;
typedef int32_t  clfs_soff_t;

typedef uint32_t clfs_block_t;

/* 说明：最长长度定义 */
// 最大名称大小(以字节为单位)，可以重新定义以减少info结构体的大小。限制为<= 1022。存储在超级块中。
#ifndef CLFS_NAME_MAX
#define CLFS_NAME_MAX 255
#endif

// 单个文件的最大大小（以字节为单位），可以重新定义以限制支持其他驱动程序，限制为<= 4294967296。
// 但是，在2147483647以上的函数clfs_file_seek、clfs_file_size和clfs_file_tell将返回不正确的值，
// 因为使用了有符号整数。存储在超级块中。
#ifndef CLFS_FILE_MAX
#define CLFS_FILE_MAX 2147483647
#endif

// 自定义属性的最大大小(以字节为单位)可以重新定义，但是使用较小的CLFS_ATTR_MAX会有隐患，限制为<= 1022。
#ifndef CLFS_ATTR_MAX
#define CLFS_ATTR_MAX 1022
#endif

/* 说明：错误码 */
// 都是负数，以允许有效的正返回值
enum clfs_error {
    CLFS_ERR_OK          = 0,                        /* 没有错误            */
    CLFS_ERR_IO          = -5,                       /* 发生在设备操作的错误 */
    CLFS_ERR_CORRUPT     = -84,                      /* Corrupted          */
    CLFS_ERR_NOENT       = -2,                       /* 缺少目录的entry     */
    CLFS_ERR_EXIST       = -17,                      /* Entry已经存在       */
    CLFS_ERR_NOTDIR      = -20,                      /* Entry不是一个目录   */
    CLFS_ERR_ISDIR       = -21,                      /* Entry是一个目录     */
    CLFS_ERR_NOTEMPTY    = -39,                      /* 目录不为空          */
    CLFS_ERR_BADF        = -9,                       /* 坏的文件号          */
    CLFS_ERR_FBIG        = -27,                      /* 文件过大            */
    CLFS_ERR_INVAL       = -22,                      /* 无效参数            */
    CLFS_ERR_NOSPC       = -28,                      /* 设备没有多余的空间   */
    CLFS_ERR_NOMEM       = -12,                      /* 没有多余的存储       */
    CLFS_ERR_NOATTR      = -61,                      /* 没有数据或属性提供    */
    CLFS_ERR_NAMETOOLONG = -36,                      /* 文件名过长           */
};

/* 说明：文件类型 */
enum clfs_type {
    // 文件类型
    CLFS_TYPE_REG            = 0x001,
    CLFS_TYPE_DIR            = 0x002,
    CLFS_TYPE_SLINK          = 0x004,                 /* 新增软链接类型       */
    CLFS_TYPE_HLINK          = 0x008,                 /* 新增硬链接类型       */

    // 内部类型（详细说明见SPEC.md）
    CLFS_TYPE_SPLICE         = 0x400,
    CLFS_TYPE_NAME           = 0x000,
    CLFS_TYPE_STRUCT         = 0x200,
    CLFS_TYPE_USERATTR       = 0x300,
    CLFS_TYPE_FROM           = 0x100,
    CLFS_TYPE_TAIL           = 0x600,
    CLFS_TYPE_GLOBALS        = 0x700,
    CLFS_TYPE_CRC            = 0x500,

    // 内部专用类型（详细说明见SPEC.md）
    CLFS_TYPE_CREATE         = 0x401,
    CLFS_TYPE_DELETE         = 0x4ff,
    CLFS_TYPE_SUPERBLOCK     = 0x0ff,
    CLFS_TYPE_DIRSTRUCT      = 0x200,
    CLFS_TYPE_CTZSTRUCT      = 0x202,
    CLFS_TYPE_INLINESTRUCT   = 0x201,
    CLFS_TYPE_SOFTTAIL       = 0x600,
    CLFS_TYPE_HARDTAIL       = 0x601,
    CLFS_TYPE_MOVESTATE      = 0x7ff,

    // 内部 chip sources
    CLFS_FROM_NOOP           = 0x000,
    CLFS_FROM_MOVE           = 0x101,
    CLFS_FROM_USERATTRS      = 0x102,
};


/* 说明：文件打开flag */
enum lfs_open_flags { //TODO
    CLFS_O_RDONLY = 1,                        /* 只读打开文件                 */
#ifndef LFS_READONLY
    CLFS_O_WRONLY = 2,                        /* 只写打开文件                 */
    CLFS_O_RDWR   = 3,                        /* 读与写打开文件               */
    CLFS_O_CREAT  = 0x0100,                   /* 如果该文件不存在，创建一个文件 */
    CLFS_O_EXCL   = 0x0200,                   /* 如果文件存在，失败            */
    CLFS_O_TRUNC  = 0x0400,                   /* 将现有文件截断为零大小        */
    CLFS_O_APPEND = 0x0800,                   /* 每次写移动到文件的末尾        */
#endif

/* 说明：内部使用flag */
#ifndef LFS_READONLY
    CLFS_F_DIRTY   = 0x010000,                   /* 文件与存储不匹配             */
    CLFS_F_WRITING = 0x020000,                   /* 自上次flush，文件被写过      */
#endif
    CLFS_F_READING = 0x040000,                   /* 自上次flush，文件被读过      */
#ifndef LFS_READONLY
    CLFS_F_ERRED   = 0x080000,                   /* 写时发生错误                 */
#endif
    CLFS_F_INLINE  = 0x100000,                   /* 当前目录的entry inline       */
};

/* 说明：文件置位flag  */
enum clfs_whence_flags {
    CLFS_SEEK_SET = 0,                           /* 求相对于绝对位置              */
    CLFS_SEEK_CUR = 1,                           /* 求相对于当前文件位置          */
    CLFS_SEEK_END = 2,                           /* 求相对于当前文件结尾位置       */
};

/*********************************************************************************************************
  外部数据结构
*********************************************************************************************************/

/* 说明：在clfs初始化期间提供的配置 */
struct clfs_config {
    // TODO 还不知道怎么用？？？不透明的用户提供的上下文可用于向块设备操作传递信息
    void *context;

    // 读取块中的一个区域。负的错误码被传播给用户。
    int (*read)(const struct clfs_config *c, clfs_block_t block,
            clfs_off_t off, void *buffer, clfs_size_t size);

    // 对一个块中的一个区域进行写入。该块之前必须被擦除。负的错误码被传播给用户。
    // 如果块被认为是坏的，可能返回CLFS_ERR_CORRUPT。
    int (*prog)(const struct clfs_config *c, clfs_block_t block,
            clfs_off_t off, const void *buffer, clfs_size_t size);

    // 抹去一块。在编写程序之前，必须先将一个块擦除。擦除块的状态未定义。
    // 负的错误码被传播给用户。如果块被认为是坏的，可能返回CLFS_ERR_CORRUPT。
    int (*erase)(const struct clfs_config *c, clfs_block_t block);

    // 同步底层块设备的状态。负的错误码被传播给用户。
    int (*sync)(const struct clfs_config *c);

#ifdef CLFS_THREADSAFE
    // 锁定底层块设备。负的错误码被传播给用户。
    int (*lock)(const struct clfs_config *c);

    // 解锁底层块设备。负的错误码被传播给用户。
    int (*unlock)(const struct clfs_config *c);
#endif

    // 以字节为单位读取的块的最小大小。所有读操作都是该值的倍数。
    clfs_size_t read_size;

    // 以字节为单位的块程序的最小大小。所有程序操作都是该值的倍数。
    clfs_size_t prog_size;

    // 可擦块的大小(以字节为单位)，这不会影响ram的消耗，而且可能会大于物理擦除的大小。
    // 非内联文件至少占用一个块，必须是读取大小和程序大小的倍数。
    clfs_size_t block_size;

    // 设备上可擦除块的数量。
    clfs_size_t block_count;

    // 在clfs删除元数据日志并将元数据移动到另一个块之前的擦除周期数，建议数值在100 ~ 1000之间。
    // 数值越大，性能越好，但磨损分布越不平衡。设置为-1将禁用块级损耗均衡。
    int32_t block_cycles;

    // 以字节为单位的块缓存的大小。每个缓存在RAM中缓存一个块的一部分。
    // clfs需要一个读缓存，一个写缓存，以及每个文件一个额外的缓存。
    // 较大的缓存可以存储更多的数据并减少磁盘访问次数，从而提高性能，但带来更大RAM开销。
    // 必须是读取和程序大小的倍数，以及块大小的一个因子。
    clfs_size_t cache_size;

    // 以字节为单位的前向缓存区的大小，更大的前向缓存区会增加分配过程中发现的块的数量。
    // 前瞻缓存区存储为一个紧凑的位图，因此RAM的每个字节可以跟踪8个块，必须是8的倍数。
    clfs_size_t lookahead_size;

    // 可选静态分配读缓存区，必须cache_size。
    // 默认情况下，使用clfs_malloc来分配这个缓存区。
    void *read_buffer;

    // 可选静态分配程序缓存区，必须cache_size。
    // 默认情况下，使用clfs_malloc来分配这个缓存区。
    void *prog_buffer;

    // 可选静态分配的前向缓存区。必须是lookahead_size并对齐到32位边界。
    // 默认情况下，使用clfs_malloc来分配这个缓存区。
    void *lookahead_buffer;

    // 可选的文件名长度上限(以字节为单位)。
    // 除了info结构的大小由CLFS_NAME_MAX定义控制之外，设的大没有坏处。
    // 设为0时默认为CLFS_NAME_MAX。存储在超级块中，必须被其他的clfs驱动重用。
    clfs_size_t name_max;

    // 可选的文件字节数上限。对于较大的文件没有缺点，但必须<= CLFS_FILE_MAX。
    // 0时默认为CLFS_FILE_MAX。存储在超级块中。
    clfs_size_t file_max;

    // 自定义属性(以字节为单位)的可选上限，设更大上限没有坏处，
    // 但必须<= CLFS_ATTR_MAX。0时默认为CLFS_ATTR_MAX。
    clfs_size_t attr_max;

    // 给元数据对的总空间(以字节为单位)的可选上限，在具有较大块(例如128kB)的设备上，
    // 将其设置为较低的大小(2-8kB)有助于限制元数据压缩时间，必须是<= block_size。0时默认为block_size。
    clfs_size_t metadata_max;
};

/* 说明：文件信息结构 */
struct clfs_info {
    // 文件类型，CLFS_TYPE_REG或CLFS_TYPE_DIR
    uint8_t type;

    // 文件的大小，仅对REG文件有效。限制为32位。
    clfs_size_t size;

    // 存储为以空结尾的字符串的文件名称，限制为CLFS_NAME_MAX+1。
    // 可以通过重新定义CLFS_NAME_MAX来减少RAM。
    // CLFS_NAME_MAX存储在超级块中，必须被其他的clfs驱动遵守。
    char name[CLFS_NAME_MAX+1];
};

/* 说明：自定义属性结构，用于描述在文件写入期间以原子方式提交的自定义属性 */
struct clfs_attr {
    // 8位类型的属性，由用户提供，用于识别属性
    uint8_t type;

    // 指向包含属性的缓存区的指针
    void *buffer;

    // 属性大小(以字节为单位)，限制为CLFS_ATTR_MAX
    clfs_size_t size;
};

/* 说明：打开文件期间提供的可选配置 */
struct clfs_file_config {
    // 可选静态分配的文件缓存区。必须cache_size。默认情况下，使用clfs_malloc来分配这个缓存区。
    void *buffer;

    // 与文件相关的可选自定义属性列表。
    // 如果文件是用读访问打开的，那么在打开调用期间将从磁盘读取这些属性。
    // 如果文件是用写访问打开的，那么在文件同步或关闭时，这些属性将被写入磁盘。这个写操作随着文件内容的更新而自动发生。
    // 自定义属性以唯一的8-bit-type标记（参考SPEC.md中的图示)，并限制为CLFS_ATTR_MAX字节。
    // 读取时，如果存储的属性小于缓存区，则将用零填充；
    // 如果存储的属性较大，则会自动截断；如果未找到该属性，将隐式创建该属性。
    struct clfs_attr *attrs;

    // 列表中的自定义属性数
    clfs_size_t attr_count;
};

/*********************************************************************************************************
  内部数据结构
*********************************************************************************************************/

/* 说明：clfs缓存类型 */
typedef struct clfs_cache {
    clfs_block_t block;                 /* 所属块号              */
    clfs_off_t off;                     /* 块内偏移              */
    clfs_size_t size;                   /* 数据大小              */
    uint8_t *buffer;                   /* 信息缓冲区            */
} clfs_cache_t;

/* 说明：底层目录数据块 */
typedef struct clfs_mdir {
    clfs_block_t pair[2];               /* 所属元数据对块号   */
    uint32_t rev;                      /* 块的版本计数          */
    clfs_off_t off;                     /* 块内偏移                 */
    uint32_t etag;                     /* TODO       */
    uint16_t count;                    /* 当前总的条目数       */
    bool erased;                       /* 是否已擦除              */
    bool split;                        /* 是否拆分                  */
    clfs_block_t tail[2];               /* 下一元数据对块号    */
} clfs_mdir_t;

/* 说明：clfs目录类型 */
typedef struct clfs_dir {
    struct clfs_dir *next;              /* 目录串成一个链表        */
    uint16_t id;                       /* 目录标识                     */
    uint8_t type;                      /* 8-bit类型                   */
    clfs_mdir_t m;                      /* 指向的目录数据块        */

    clfs_off_t pos;                     /* 目录指针的位置            */
    clfs_block_t head[2];               /* 前一元数据对的块号     */
} clfs_dir_t;

/* 说明：clfs文件类型 */
typedef struct clfs_file {
    struct clfs_file *next;
    uint16_t id;                       /* 文件标识          */
    uint8_t type;                      /* 8-bit类型        */
    clfs_mdir_t m;                      /* 指向的目录数据块  */

    struct clfs_ctz {
        clfs_block_t head;
        clfs_size_t size;
    } ctz;                             /* TODO   */

    uint32_t flags;                    /* 文件打开标志          */
    clfs_off_t pos;                     /* 目前的文件指针位置     */
    clfs_block_t block;                 /* 块号                  */
    clfs_off_t off;                     /* 块内偏移              */
    clfs_cache_t cache;                 /* 数据缓存              */

    const struct clfs_file_config *cfg; /* 用户属性相关          */
} clfs_file_t;

/* 说明：clfs超级块 */
typedef struct clfs_superblock {
    uint32_t version;                   /* ClFs版本         */
    clfs_size_t block_size;              /* 块大小               */
    clfs_size_t block_count;             /* 块总数               */
    clfs_size_t name_max;                /* 名称最大长度          */
    clfs_size_t file_max;                /* 文件最大长度          */
    clfs_size_t attr_max;                /* 用户属性最大长度      */
} clfs_superblock_t;

/* 说明：clfs全局状态 */
typedef struct clfs_gstate {
    uint32_t tag;
    clfs_block_t pair[2];
} clfs_gstate_t;

/* 说明：clfs文件系统类型 */
typedef struct clfs {
    clfs_cache_t rcache;                 /* 读缓存               */
    clfs_cache_t pcache;                 /* 写缓存               */

    clfs_block_t root[2];                /* 根目录所属元数据对块号 */
    struct clfs_mlist {
        struct clfs_mlist *next;
        uint16_t id;
        uint8_t type;
        clfs_mdir_t m;
    } *mlist;                           /* 打开文件链表，目录/文件通用，前四个条目相同  */
    uint32_t seed;                      /* 随机数种子            */

    clfs_gstate_t gstate;                /* 全局状态              */
    clfs_gstate_t gdisk;                 /* 原状态                */
    clfs_gstate_t gdelta;                /* 状态增量              */

    struct clfs_free {
        clfs_block_t off; //首部块的偏移（相对于设备上的首块）
        clfs_block_t size;//lookahead总的块的数目
        clfs_block_t i;   //当前块号（相对于lookahead的首块）
        clfs_block_t ack; //分配的块已提交到文件系统
        uint32_t *buffer;//缓存地址
    } free;                             /* 待分配的块分配表        */

    const struct clfs_config *cfg;
    clfs_size_t name_max;
    clfs_size_t file_max;
    clfs_size_t attr_max;

#ifdef CLFS_MIGRATE
    struct clfs1 *clfs1;
#endif
} clfs_t;


/*********************************************************************************************************
  文件系统相关函数
*********************************************************************************************************/

#ifndef CLFS_READONLY

/* 说明：用clfs格式化块设备 */
// 需要clfs对象和clfs_config配置结构体。这会重建clfs对象，但不会使文件系统保持挂载状态。
// clfs_config必须为零，以实现默认值和向后兼容性。失败时返回负错误代码。
int clfs_format(clfs_t *clfs, const struct clfs_config *config);
#endif

/* 说明：挂载clfs */
// 需要clfs对象和配置结构。可以使用多个clfs对象同时装载多个文件系统。
// 装载时必须同时分配clfs和clfs_config，配置结构必须为零，以实现默认值和向后兼容性。失败时返回负错误代码。
int clfs_mount(clfs_t *clfs, const struct clfs_config *config);

/* 说明：卸载clfs */
// 除了释放任何分配的资源外，什么都不做。失败时返回负错误代码。
int clfs_unmount(clfs_t *clfs);


/*********************************************************************************************************
  总的操作
*********************************************************************************************************/

#ifndef CLFS_READONLY
/* 说明：删除文件或目录 */
// 如果删除目录，目录必须为空。失败时返回负错误代码。
int clfs_remove(clfs_t *clfs, const char *path);
#endif

#ifndef CLFS_READONLY
/* 说明：删除或重命名文件或目录 */
// 如果目标存在，则其类型必须与源匹配。如果目标是目录，则目录必须为空。失败时返回负错误代码。
int clfs_rename(clfs_t *clfs, const char *oldpath, const char *newpath);
#endif

/* 说明：查找文件或目录 */
// 根据指定的文件或目录填写clfs_info信息结构。失败时返回负错误代码。
int clfs_stat(clfs_t *clfs, const char *path, struct clfs_info *info);

/* 说明：获取自定义属性 */
// 自定义属性由8-bit type 唯一标识，并限制为CLFS_ATTR_MAX字节。
// 读取时，如果存储的属性小于缓存区，则将用零填充。如果存储的属性较大，则会自动截断；
// 如果未找到属性，则返回错误CLFS_ERR_NOATTR，并用零填充缓存区。
// 返回属性的大小，或失败时返回负错误代码。
// 注意，返回的大小是磁盘上属性的大小，与缓存区的大小无关。这可用于动态分配缓存区或检查是否存在。
clfs_ssize_t clfs_getattr(clfs_t *clfs, const char *path,
        uint8_t type, void *buffer, clfs_size_t size);

#ifndef CLFS_READONLY

/* 说明：设置自定义属性 */
// 自定义属性由8-bit type唯一标识，并限制为CLFS_ATTR_MAX字节。
// 如果未找到属性，则将隐式创建该属性。失败时返回负错误代码。
int clfs_setattr(clfs_t *clfs, const char *path,
        uint8_t type, const void *buffer, clfs_size_t size);
#endif

#ifndef CLFS_READONLY
/* 说明：删除自定义属性 */
// 如果未找到属性，则不会发生任何事情。失败时返回负错误代码。
int clfs_removeattr(clfs_t *clfs, const char *path, uint8_t type);
#endif


/*********************************************************************************************************
  文件操作
*********************************************************************************************************/

#ifndef CLFS_NO_MALLOC
/* 说明：打开文件 */
// 打开文件的模式由标志决定，这些标志是枚举clfs_open_flag中的值，它们按位或在一起。失败时返回负错误代码。
int clfs_file_open(clfs_t *clfs, clfs_file_t *file,
        const char *path, int flags);
// 如果定义了CLFS_NO_MALLOC，CLFS_file_open()将因CLFS_ERR_NOMEM而失败，
// 因此将CLFS_file_opencfg()与 config.buffer 一起使用。
#endif

/* 说明：打开具有额外配置的文件 */
// 打开文件的模式由Flag决定，这些标志是clfs_open_flag中的值，它们按位或在一起。
// 如上所述，clfs_file_config为每个文件提供了额外的配置选项。
// 必须在文件打开时分配配置结构，并且必须将配置结构归零以获得默认值和向后兼容性。失败时返回负错误代码。
int clfs_file_opencfg(clfs_t *clfs, clfs_file_t *file,
        const char *path, int flags,
        const struct clfs_file_config *config);

/* 说明：关闭文件 */
// 任何缓存的写入都会写回存储，就像调用了同步一样，并释放任何分配的资源。失败时返回负错误代码。
int clfs_file_close(clfs_t *clfs, clfs_file_t *file);

/* 说明：同步存储上的文件 */
// 任何缓存的写入都会写回存储。失败时返回负错误代码。
int clfs_file_sync(clfs_t *clfs, clfs_file_t *file);

/* 说明：从文件中读取数据 */
// 获取一个缓存区和大小，指示读取数据的存储位置。返回读取的字节数，或失败时返回负错误代码。
clfs_ssize_t clfs_file_read(clfs_t *clfs, clfs_file_t *file,
        void *buffer, clfs_size_t size);

#ifndef CLFS_READONLY
/* 说明：从文件中写入数据 */
// 获取指示要写入的数据的缓存区和大小。在调用sync或close之前，不会在存储上实际更新文件。
// 返回写入的字节数，或失败时返回负错误代码。
clfs_ssize_t clfs_file_write(clfs_t *clfs, clfs_file_t *file,
        const void *buffer, clfs_size_t size);
#endif

/* 说明：改变文件位置 */
// 位置变化由偏移和位置标志确定。返回文件的新位置，或失败时返回负错误代码。
clfs_soff_t clfs_file_seek(clfs_t *clfs, clfs_file_t *file,
        clfs_soff_t off, int whence);

#ifndef CLFS_READONLY
/* 说明：将文件大小截断为指定大小 */
int clfs_file_truncate(clfs_t *clfs, clfs_file_t *file, clfs_off_t size);
#endif

/* 说明: 返回文件位置*/
clfs_soff_t clfs_file_tell(clfs_t *clfs, clfs_file_t *file);

/* 说明：将文件当前的位置更改为文件的开头 */
int clfs_file_rewind(clfs_t *clfs, clfs_file_t *file);

/* 说明: 返回文件大小*/
clfs_soff_t clfs_file_size(clfs_t *clfs, clfs_file_t *file);


/*********************************************************************************************************
  目录操作
*********************************************************************************************************/

#ifndef CLFS_READONLY
/* 说明: 创建目录 */
// 失败时返回负错误代码。
int clfs_mkdir(clfs_t *clfs, const char *path);
#endif

/* 说明: 打开目录 */
// 失败时返回负错误代码。
int clfs_dir_open(clfs_t *clfs, clfs_dir_t *dir, const char *path);

/* 说明: 关闭目录，释放任何已分配的资源 */
int clfs_dir_close(clfs_t *clfs, clfs_dir_t *dir);

/* 说明: 读目录里的一个条目 */
// 根据指定的文件或目录填写信息结构。成功时返回正值，目录末尾返回0，或故障时的负错误代码。
int clfs_dir_read(clfs_t *clfs, clfs_dir_t *dir, struct clfs_info *info);

/* 说明: 改变目录的位置 */
// 新的off必须是从tell返回的上一个值，并指定目录查找中的绝对偏移量。
// 失败时返回负错误代码。
int clfs_dir_seek(clfs_t *clfs, clfs_dir_t *dir, clfs_off_t off);

/* 说明: 返回目录的位置 */
// 返回的偏移量仅用于seek，可能无法生成，但确实指示目录迭代中的当前位置。
// 返回目录的位置，或失败时返回负错误代码。
clfs_soff_t clfs_dir_tell(clfs_t *clfs, clfs_dir_t *dir);

/* 说明: 将目录的位置更改为目录的开头 */
// 失败时返回负错误代码。
int clfs_dir_rewind(clfs_t *clfs, clfs_dir_t *dir);


/*********************************************************************************************************
  文件系统操作
*********************************************************************************************************/

/* 说明: 文件系统的当前大小 */
// 如果文件共享COW结构，则返回小可能大于文件系统的实际大小。
// 返回分配的块数，或失败时返回负错误代码。
clfs_ssize_t clfs_fs_size(clfs_t *clfs);

/* 说明: 遍历文件系统正在使用的所有块 */
// 所提供的回调将被文件系统当前使用的每个块地址调用，这可以用来确定哪些块正在使用，或者有多少存储可用
int clfs_fs_traverse(clfs_t *clfs, int (*cb)(void*, clfs_block_t), void *data);

#ifndef CLFS_READONLY
#ifdef CLFS_MIGRATE

/* 说明：尝试迁移之前版本的clfs */
int clfs_migrate(clfs_t *clfs, const struct clfs_config *cfg);

#endif
#endif


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
