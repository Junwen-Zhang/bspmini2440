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
** ��   ��   ��: clfs.h
**
** ��   ��   ��: �¿���
**
** �ļ���������: 2022 �� 06 �� 04 ��
**
** ��        ��: clfs��ع��߰���h�ļ�
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
  �汾��Ϣ
*********************************************************************************************************/

/* ˵���������汾 */
#define CLFS_VERSION 0x00020005
#define CLFS_VERSION_MAJOR (0xffff & (CLFS_VERSION >> 16))
#define CLFS_VERSION_MINOR (0xffff & (CLFS_VERSION >>  0))

/* ˵�������������ݽṹ�İ汾 */
#define CLFS_DISK_VERSION 0x00020000
#define CLFS_DISK_VERSION_MAJOR (0xffff & (CLFS_DISK_VERSION >> 16))
#define CLFS_DISK_VERSION_MINOR (0xffff & (CLFS_DISK_VERSION >>  0))

/*********************************************************************************************************
  �ڲ�����
*********************************************************************************************************/
/* ˵�������Ͷ��� */
typedef uint32_t clfs_size_t;
typedef uint32_t clfs_off_t;

typedef int32_t  clfs_ssize_t;
typedef int32_t  clfs_soff_t;

typedef uint32_t clfs_block_t;

/* ˵��������ȶ��� */
// ������ƴ�С(���ֽ�Ϊ��λ)���������¶����Լ���info�ṹ��Ĵ�С������Ϊ<= 1022���洢�ڳ������С�
#ifndef CLFS_NAME_MAX
#define CLFS_NAME_MAX 255
#endif

// �����ļ�������С�����ֽ�Ϊ��λ�����������¶���������֧������������������Ϊ<= 4294967296��
// ���ǣ���2147483647���ϵĺ���clfs_file_seek��clfs_file_size��clfs_file_tell�����ز���ȷ��ֵ��
// ��Ϊʹ�����з����������洢�ڳ������С�
#ifndef CLFS_FILE_MAX
#define CLFS_FILE_MAX 2147483647
#endif

// �Զ������Ե�����С(���ֽ�Ϊ��λ)�������¶��壬����ʹ�ý�С��CLFS_ATTR_MAX��������������Ϊ<= 1022��
#ifndef CLFS_ATTR_MAX
#define CLFS_ATTR_MAX 1022
#endif

/* ˵���������� */
// ���Ǹ�������������Ч��������ֵ
enum clfs_error {
    CLFS_ERR_OK          = 0,                        /* û�д���            */
    CLFS_ERR_IO          = -5,                       /* �������豸�����Ĵ��� */
    CLFS_ERR_CORRUPT     = -84,                      /* Corrupted          */
    CLFS_ERR_NOENT       = -2,                       /* ȱ��Ŀ¼��entry     */
    CLFS_ERR_EXIST       = -17,                      /* Entry�Ѿ�����       */
    CLFS_ERR_NOTDIR      = -20,                      /* Entry����һ��Ŀ¼   */
    CLFS_ERR_ISDIR       = -21,                      /* Entry��һ��Ŀ¼     */
    CLFS_ERR_NOTEMPTY    = -39,                      /* Ŀ¼��Ϊ��          */
    CLFS_ERR_BADF        = -9,                       /* �����ļ���          */
    CLFS_ERR_FBIG        = -27,                      /* �ļ�����            */
    CLFS_ERR_INVAL       = -22,                      /* ��Ч����            */
    CLFS_ERR_NOSPC       = -28,                      /* �豸û�ж���Ŀռ�   */
    CLFS_ERR_NOMEM       = -12,                      /* û�ж���Ĵ洢       */
    CLFS_ERR_NOATTR      = -61,                      /* û�����ݻ������ṩ    */
    CLFS_ERR_NAMETOOLONG = -36,                      /* �ļ�������           */
};

/* ˵�����ļ����� */
enum clfs_type {
    // �ļ�����
    CLFS_TYPE_REG            = 0x001,
    CLFS_TYPE_DIR            = 0x002,
    CLFS_TYPE_SLINK          = 0x004,                 /* ��������������       */
    CLFS_TYPE_HLINK          = 0x008,                 /* ����Ӳ��������       */

    // �ڲ����ͣ���ϸ˵����SPEC.md��
    CLFS_TYPE_SPLICE         = 0x400,
    CLFS_TYPE_NAME           = 0x000,
    CLFS_TYPE_STRUCT         = 0x200,
    CLFS_TYPE_USERATTR       = 0x300,
    CLFS_TYPE_FROM           = 0x100,
    CLFS_TYPE_TAIL           = 0x600,
    CLFS_TYPE_GLOBALS        = 0x700,
    CLFS_TYPE_CRC            = 0x500,

    // �ڲ�ר�����ͣ���ϸ˵����SPEC.md��
    CLFS_TYPE_CREATE         = 0x401,
    CLFS_TYPE_DELETE         = 0x4ff,
    CLFS_TYPE_SUPERBLOCK     = 0x0ff,
    CLFS_TYPE_DIRSTRUCT      = 0x200,
    CLFS_TYPE_CTZSTRUCT      = 0x202,
    CLFS_TYPE_INLINESTRUCT   = 0x201,
    CLFS_TYPE_SOFTTAIL       = 0x600,
    CLFS_TYPE_HARDTAIL       = 0x601,
    CLFS_TYPE_MOVESTATE      = 0x7ff,

    // �ڲ� chip sources
    CLFS_FROM_NOOP           = 0x000,
    CLFS_FROM_MOVE           = 0x101,
    CLFS_FROM_USERATTRS      = 0x102,
};


/* ˵�����ļ���flag */
enum lfs_open_flags { //TODO
    CLFS_O_RDONLY = 1,                        /* ֻ�����ļ�                 */
#ifndef LFS_READONLY
    CLFS_O_WRONLY = 2,                        /* ֻд���ļ�                 */
    CLFS_O_RDWR   = 3,                        /* ����д���ļ�               */
    CLFS_O_CREAT  = 0x0100,                   /* ������ļ������ڣ�����һ���ļ� */
    CLFS_O_EXCL   = 0x0200,                   /* ����ļ����ڣ�ʧ��            */
    CLFS_O_TRUNC  = 0x0400,                   /* �������ļ��ض�Ϊ���С        */
    CLFS_O_APPEND = 0x0800,                   /* ÿ��д�ƶ����ļ���ĩβ        */
#endif

/* ˵�����ڲ�ʹ��flag */
#ifndef LFS_READONLY
    CLFS_F_DIRTY   = 0x010000,                   /* �ļ���洢��ƥ��             */
    CLFS_F_WRITING = 0x020000,                   /* ���ϴ�flush���ļ���д��      */
#endif
    CLFS_F_READING = 0x040000,                   /* ���ϴ�flush���ļ�������      */
#ifndef LFS_READONLY
    CLFS_F_ERRED   = 0x080000,                   /* дʱ��������                 */
#endif
    CLFS_F_INLINE  = 0x100000,                   /* ��ǰĿ¼��entry inline       */
};

/* ˵�����ļ���λflag  */
enum clfs_whence_flags {
    CLFS_SEEK_SET = 0,                           /* ������ھ���λ��              */
    CLFS_SEEK_CUR = 1,                           /* ������ڵ�ǰ�ļ�λ��          */
    CLFS_SEEK_END = 2,                           /* ������ڵ�ǰ�ļ���βλ��       */
};

/*********************************************************************************************************
  �ⲿ���ݽṹ
*********************************************************************************************************/

/* ˵������clfs��ʼ���ڼ��ṩ������ */
struct clfs_config {
    // TODO ����֪����ô�ã�������͸�����û��ṩ�������Ŀ���������豸����������Ϣ
    void *context;

    // ��ȡ���е�һ�����򡣸��Ĵ����뱻�������û���
    int (*read)(const struct clfs_config *c, clfs_block_t block,
            clfs_off_t off, void *buffer, clfs_size_t size);

    // ��һ�����е�һ���������д�롣�ÿ�֮ǰ���뱻���������Ĵ����뱻�������û���
    // ����鱻��Ϊ�ǻ��ģ����ܷ���CLFS_ERR_CORRUPT��
    int (*prog)(const struct clfs_config *c, clfs_block_t block,
            clfs_off_t off, const void *buffer, clfs_size_t size);

    // Ĩȥһ�顣�ڱ�д����֮ǰ�������Ƚ�һ����������������״̬δ���塣
    // ���Ĵ����뱻�������û�������鱻��Ϊ�ǻ��ģ����ܷ���CLFS_ERR_CORRUPT��
    int (*erase)(const struct clfs_config *c, clfs_block_t block);

    // ͬ���ײ���豸��״̬�����Ĵ����뱻�������û���
    int (*sync)(const struct clfs_config *c);

#ifdef CLFS_THREADSAFE
    // �����ײ���豸�����Ĵ����뱻�������û���
    int (*lock)(const struct clfs_config *c);

    // �����ײ���豸�����Ĵ����뱻�������û���
    int (*unlock)(const struct clfs_config *c);
#endif

    // ���ֽ�Ϊ��λ��ȡ�Ŀ����С��С�����ж��������Ǹ�ֵ�ı�����
    clfs_size_t read_size;

    // ���ֽ�Ϊ��λ�Ŀ�������С��С�����г���������Ǹ�ֵ�ı�����
    clfs_size_t prog_size;

    // �ɲ���Ĵ�С(���ֽ�Ϊ��λ)���ⲻ��Ӱ��ram�����ģ����ҿ��ܻ������������Ĵ�С��
    // �������ļ�����ռ��һ���飬�����Ƕ�ȡ��С�ͳ����С�ı�����
    clfs_size_t block_size;

    // �豸�Ͽɲ������������
    clfs_size_t block_count;

    // ��clfsɾ��Ԫ������־����Ԫ�����ƶ�����һ����֮ǰ�Ĳ�����������������ֵ��100 ~ 1000֮�䡣
    // ��ֵԽ������Խ�ã���ĥ��ֲ�Խ��ƽ�⡣����Ϊ-1�����ÿ鼶��ľ��⡣
    int32_t block_cycles;

    // ���ֽ�Ϊ��λ�Ŀ黺��Ĵ�С��ÿ��������RAM�л���һ�����һ���֡�
    // clfs��Ҫһ�������棬һ��д���棬�Լ�ÿ���ļ�һ������Ļ��档
    // �ϴ�Ļ�����Դ洢��������ݲ����ٴ��̷��ʴ������Ӷ�������ܣ�����������RAM������
    // �����Ƕ�ȡ�ͳ����С�ı������Լ����С��һ�����ӡ�
    clfs_size_t cache_size;

    // ���ֽ�Ϊ��λ��ǰ�򻺴����Ĵ�С�������ǰ�򻺴��������ӷ�������з��ֵĿ��������
    // ǰհ�������洢Ϊһ�����յ�λͼ�����RAM��ÿ���ֽڿ��Ը���8���飬������8�ı�����
    clfs_size_t lookahead_size;

    // ��ѡ��̬�����������������cache_size��
    // Ĭ������£�ʹ��clfs_malloc�����������������
    void *read_buffer;

    // ��ѡ��̬������򻺴���������cache_size��
    // Ĭ������£�ʹ��clfs_malloc�����������������
    void *prog_buffer;

    // ��ѡ��̬�����ǰ�򻺴�����������lookahead_size�����뵽32λ�߽硣
    // Ĭ������£�ʹ��clfs_malloc�����������������
    void *lookahead_buffer;

    // ��ѡ���ļ�����������(���ֽ�Ϊ��λ)��
    // ����info�ṹ�Ĵ�С��CLFS_NAME_MAX�������֮�⣬��Ĵ�û�л�����
    // ��Ϊ0ʱĬ��ΪCLFS_NAME_MAX���洢�ڳ������У����뱻������clfs�������á�
    clfs_size_t name_max;

    // ��ѡ���ļ��ֽ������ޡ����ڽϴ���ļ�û��ȱ�㣬������<= CLFS_FILE_MAX��
    // 0ʱĬ��ΪCLFS_FILE_MAX���洢�ڳ������С�
    clfs_size_t file_max;

    // �Զ�������(���ֽ�Ϊ��λ)�Ŀ�ѡ���ޣ����������û�л�����
    // ������<= CLFS_ATTR_MAX��0ʱĬ��ΪCLFS_ATTR_MAX��
    clfs_size_t attr_max;

    // ��Ԫ���ݶԵ��ܿռ�(���ֽ�Ϊ��λ)�Ŀ�ѡ���ޣ��ھ��нϴ��(����128kB)���豸�ϣ�
    // ��������Ϊ�ϵ͵Ĵ�С(2-8kB)����������Ԫ����ѹ��ʱ�䣬������<= block_size��0ʱĬ��Ϊblock_size��
    clfs_size_t metadata_max;
};

/* ˵�����ļ���Ϣ�ṹ */
struct clfs_info {
    // �ļ����ͣ�CLFS_TYPE_REG��CLFS_TYPE_DIR
    uint8_t type;

    // �ļ��Ĵ�С������REG�ļ���Ч������Ϊ32λ��
    clfs_size_t size;

    // �洢Ϊ�Կս�β���ַ������ļ����ƣ�����ΪCLFS_NAME_MAX+1��
    // ����ͨ�����¶���CLFS_NAME_MAX������RAM��
    // CLFS_NAME_MAX�洢�ڳ������У����뱻������clfs�������ء�
    char name[CLFS_NAME_MAX+1];
};

/* ˵�����Զ������Խṹ�������������ļ�д���ڼ���ԭ�ӷ�ʽ�ύ���Զ������� */
struct clfs_attr {
    // 8λ���͵����ԣ����û��ṩ������ʶ������
    uint8_t type;

    // ָ��������ԵĻ�������ָ��
    void *buffer;

    // ���Դ�С(���ֽ�Ϊ��λ)������ΪCLFS_ATTR_MAX
    clfs_size_t size;
};

/* ˵�������ļ��ڼ��ṩ�Ŀ�ѡ���� */
struct clfs_file_config {
    // ��ѡ��̬������ļ�������������cache_size��Ĭ������£�ʹ��clfs_malloc�����������������
    void *buffer;

    // ���ļ���صĿ�ѡ�Զ��������б�
    // ����ļ����ö����ʴ򿪵ģ���ô�ڴ򿪵����ڼ佫�Ӵ��̶�ȡ��Щ���ԡ�
    // ����ļ�����д���ʴ򿪵ģ���ô���ļ�ͬ����ر�ʱ����Щ���Խ���д����̡����д���������ļ����ݵĸ��¶��Զ�������
    // �Զ���������Ψһ��8-bit-type��ǣ��ο�SPEC.md�е�ͼʾ)��������ΪCLFS_ATTR_MAX�ֽڡ�
    // ��ȡʱ������洢������С�ڻ���������������䣻
    // ����洢�����Խϴ�����Զ��ضϣ����δ�ҵ������ԣ�����ʽ���������ԡ�
    struct clfs_attr *attrs;

    // �б��е��Զ���������
    clfs_size_t attr_count;
};

/*********************************************************************************************************
  �ڲ����ݽṹ
*********************************************************************************************************/

/* ˵����clfs�������� */
typedef struct clfs_cache {
    clfs_block_t block;                 /* �������              */
    clfs_off_t off;                     /* ����ƫ��              */
    clfs_size_t size;                   /* ���ݴ�С              */
    uint8_t *buffer;                   /* ��Ϣ������            */
} clfs_cache_t;

/* ˵�����ײ�Ŀ¼���ݿ� */
typedef struct clfs_mdir {
    clfs_block_t pair[2];               /* ����Ԫ���ݶԿ��   */
    uint32_t rev;                      /* ��İ汾����          */
    clfs_off_t off;                     /* ����ƫ��                 */
    uint32_t etag;                     /* TODO       */
    uint16_t count;                    /* ��ǰ�ܵ���Ŀ��       */
    bool erased;                       /* �Ƿ��Ѳ���              */
    bool split;                        /* �Ƿ���                  */
    clfs_block_t tail[2];               /* ��һԪ���ݶԿ��    */
} clfs_mdir_t;

/* ˵����clfsĿ¼���� */
typedef struct clfs_dir {
    struct clfs_dir *next;              /* Ŀ¼����һ������        */
    uint16_t id;                       /* Ŀ¼��ʶ                     */
    uint8_t type;                      /* 8-bit����                   */
    clfs_mdir_t m;                      /* ָ���Ŀ¼���ݿ�        */

    clfs_off_t pos;                     /* Ŀ¼ָ���λ��            */
    clfs_block_t head[2];               /* ǰһԪ���ݶԵĿ��     */
} clfs_dir_t;

/* ˵����clfs�ļ����� */
typedef struct clfs_file {
    struct clfs_file *next;
    uint16_t id;                       /* �ļ���ʶ          */
    uint8_t type;                      /* 8-bit����        */
    clfs_mdir_t m;                      /* ָ���Ŀ¼���ݿ�  */

    struct clfs_ctz {
        clfs_block_t head;
        clfs_size_t size;
    } ctz;                             /* TODO   */

    uint32_t flags;                    /* �ļ��򿪱�־          */
    clfs_off_t pos;                     /* Ŀǰ���ļ�ָ��λ��     */
    clfs_block_t block;                 /* ���                  */
    clfs_off_t off;                     /* ����ƫ��              */
    clfs_cache_t cache;                 /* ���ݻ���              */

    const struct clfs_file_config *cfg; /* �û��������          */
} clfs_file_t;

/* ˵����clfs������ */
typedef struct clfs_superblock {
    uint32_t version;                   /* ClFs�汾         */
    clfs_size_t block_size;              /* ���С               */
    clfs_size_t block_count;             /* ������               */
    clfs_size_t name_max;                /* ������󳤶�          */
    clfs_size_t file_max;                /* �ļ���󳤶�          */
    clfs_size_t attr_max;                /* �û�������󳤶�      */
} clfs_superblock_t;

/* ˵����clfsȫ��״̬ */
typedef struct clfs_gstate {
    uint32_t tag;
    clfs_block_t pair[2];
} clfs_gstate_t;

/* ˵����clfs�ļ�ϵͳ���� */
typedef struct clfs {
    clfs_cache_t rcache;                 /* ������               */
    clfs_cache_t pcache;                 /* д����               */

    clfs_block_t root[2];                /* ��Ŀ¼����Ԫ���ݶԿ�� */
    struct clfs_mlist {
        struct clfs_mlist *next;
        uint16_t id;
        uint8_t type;
        clfs_mdir_t m;
    } *mlist;                           /* ���ļ�����Ŀ¼/�ļ�ͨ�ã�ǰ�ĸ���Ŀ��ͬ  */
    uint32_t seed;                      /* ���������            */

    clfs_gstate_t gstate;                /* ȫ��״̬              */
    clfs_gstate_t gdisk;                 /* ԭ״̬                */
    clfs_gstate_t gdelta;                /* ״̬����              */

    struct clfs_free {
        clfs_block_t off; //�ײ����ƫ�ƣ�������豸�ϵ��׿飩
        clfs_block_t size;//lookahead�ܵĿ����Ŀ
        clfs_block_t i;   //��ǰ��ţ������lookahead���׿飩
        clfs_block_t ack; //����Ŀ����ύ���ļ�ϵͳ
        uint32_t *buffer;//�����ַ
    } free;                             /* ������Ŀ�����        */

    const struct clfs_config *cfg;
    clfs_size_t name_max;
    clfs_size_t file_max;
    clfs_size_t attr_max;

#ifdef CLFS_MIGRATE
    struct clfs1 *clfs1;
#endif
} clfs_t;


/*********************************************************************************************************
  �ļ�ϵͳ��غ���
*********************************************************************************************************/

#ifndef CLFS_READONLY

/* ˵������clfs��ʽ�����豸 */
// ��Ҫclfs�����clfs_config���ýṹ�塣����ؽ�clfs���󣬵�����ʹ�ļ�ϵͳ���ֹ���״̬��
// clfs_config����Ϊ�㣬��ʵ��Ĭ��ֵ���������ԡ�ʧ��ʱ���ظ�������롣
int clfs_format(clfs_t *clfs, const struct clfs_config *config);
#endif

/* ˵��������clfs */
// ��Ҫclfs��������ýṹ������ʹ�ö��clfs����ͬʱװ�ض���ļ�ϵͳ��
// װ��ʱ����ͬʱ����clfs��clfs_config�����ýṹ����Ϊ�㣬��ʵ��Ĭ��ֵ���������ԡ�ʧ��ʱ���ظ�������롣
int clfs_mount(clfs_t *clfs, const struct clfs_config *config);

/* ˵����ж��clfs */
// �����ͷ��κη������Դ�⣬ʲô��������ʧ��ʱ���ظ�������롣
int clfs_unmount(clfs_t *clfs);


/*********************************************************************************************************
  �ܵĲ���
*********************************************************************************************************/

#ifndef CLFS_READONLY
/* ˵����ɾ���ļ���Ŀ¼ */
// ���ɾ��Ŀ¼��Ŀ¼����Ϊ�ա�ʧ��ʱ���ظ�������롣
int clfs_remove(clfs_t *clfs, const char *path);
#endif

#ifndef CLFS_READONLY
/* ˵����ɾ�����������ļ���Ŀ¼ */
// ���Ŀ����ڣ��������ͱ�����Դƥ�䡣���Ŀ����Ŀ¼����Ŀ¼����Ϊ�ա�ʧ��ʱ���ظ�������롣
int clfs_rename(clfs_t *clfs, const char *oldpath, const char *newpath);
#endif

/* ˵���������ļ���Ŀ¼ */
// ����ָ�����ļ���Ŀ¼��дclfs_info��Ϣ�ṹ��ʧ��ʱ���ظ�������롣
int clfs_stat(clfs_t *clfs, const char *path, struct clfs_info *info);

/* ˵������ȡ�Զ������� */
// �Զ���������8-bit type Ψһ��ʶ��������ΪCLFS_ATTR_MAX�ֽڡ�
// ��ȡʱ������洢������С�ڻ���������������䡣����洢�����Խϴ�����Զ��ضϣ�
// ���δ�ҵ����ԣ��򷵻ش���CLFS_ERR_NOATTR����������仺������
// �������ԵĴ�С����ʧ��ʱ���ظ�������롣
// ע�⣬���صĴ�С�Ǵ��������ԵĴ�С���뻺�����Ĵ�С�޹ء�������ڶ�̬���仺���������Ƿ���ڡ�
clfs_ssize_t clfs_getattr(clfs_t *clfs, const char *path,
        uint8_t type, void *buffer, clfs_size_t size);

#ifndef CLFS_READONLY

/* ˵���������Զ������� */
// �Զ���������8-bit typeΨһ��ʶ��������ΪCLFS_ATTR_MAX�ֽڡ�
// ���δ�ҵ����ԣ�����ʽ���������ԡ�ʧ��ʱ���ظ�������롣
int clfs_setattr(clfs_t *clfs, const char *path,
        uint8_t type, const void *buffer, clfs_size_t size);
#endif

#ifndef CLFS_READONLY
/* ˵����ɾ���Զ������� */
// ���δ�ҵ����ԣ��򲻻ᷢ���κ����顣ʧ��ʱ���ظ�������롣
int clfs_removeattr(clfs_t *clfs, const char *path, uint8_t type);
#endif


/*********************************************************************************************************
  �ļ�����
*********************************************************************************************************/

#ifndef CLFS_NO_MALLOC
/* ˵�������ļ� */
// ���ļ���ģʽ�ɱ�־��������Щ��־��ö��clfs_open_flag�е�ֵ�����ǰ�λ����һ��ʧ��ʱ���ظ�������롣
int clfs_file_open(clfs_t *clfs, clfs_file_t *file,
        const char *path, int flags);
// ���������CLFS_NO_MALLOC��CLFS_file_open()����CLFS_ERR_NOMEM��ʧ�ܣ�
// ��˽�CLFS_file_opencfg()�� config.buffer һ��ʹ�á�
#endif

/* ˵�����򿪾��ж������õ��ļ� */
// ���ļ���ģʽ��Flag��������Щ��־��clfs_open_flag�е�ֵ�����ǰ�λ����һ��
// ����������clfs_file_configΪÿ���ļ��ṩ�˶��������ѡ�
// �������ļ���ʱ�������ýṹ�����ұ��뽫���ýṹ�����Ի��Ĭ��ֵ���������ԡ�ʧ��ʱ���ظ�������롣
int clfs_file_opencfg(clfs_t *clfs, clfs_file_t *file,
        const char *path, int flags,
        const struct clfs_file_config *config);

/* ˵�����ر��ļ� */
// �κλ����д�붼��д�ش洢�����������ͬ��һ�������ͷ��κη������Դ��ʧ��ʱ���ظ�������롣
int clfs_file_close(clfs_t *clfs, clfs_file_t *file);

/* ˵����ͬ���洢�ϵ��ļ� */
// �κλ����д�붼��д�ش洢��ʧ��ʱ���ظ�������롣
int clfs_file_sync(clfs_t *clfs, clfs_file_t *file);

/* ˵�������ļ��ж�ȡ���� */
// ��ȡһ���������ʹ�С��ָʾ��ȡ���ݵĴ洢λ�á����ض�ȡ���ֽ�������ʧ��ʱ���ظ�������롣
clfs_ssize_t clfs_file_read(clfs_t *clfs, clfs_file_t *file,
        void *buffer, clfs_size_t size);

#ifndef CLFS_READONLY
/* ˵�������ļ���д������ */
// ��ȡָʾҪд������ݵĻ������ʹ�С���ڵ���sync��close֮ǰ�������ڴ洢��ʵ�ʸ����ļ���
// ����д����ֽ�������ʧ��ʱ���ظ�������롣
clfs_ssize_t clfs_file_write(clfs_t *clfs, clfs_file_t *file,
        const void *buffer, clfs_size_t size);
#endif

/* ˵�����ı��ļ�λ�� */
// λ�ñ仯��ƫ�ƺ�λ�ñ�־ȷ���������ļ�����λ�ã���ʧ��ʱ���ظ�������롣
clfs_soff_t clfs_file_seek(clfs_t *clfs, clfs_file_t *file,
        clfs_soff_t off, int whence);

#ifndef CLFS_READONLY
/* ˵�������ļ���С�ض�Ϊָ����С */
int clfs_file_truncate(clfs_t *clfs, clfs_file_t *file, clfs_off_t size);
#endif

/* ˵��: �����ļ�λ��*/
clfs_soff_t clfs_file_tell(clfs_t *clfs, clfs_file_t *file);

/* ˵�������ļ���ǰ��λ�ø���Ϊ�ļ��Ŀ�ͷ */
int clfs_file_rewind(clfs_t *clfs, clfs_file_t *file);

/* ˵��: �����ļ���С*/
clfs_soff_t clfs_file_size(clfs_t *clfs, clfs_file_t *file);


/*********************************************************************************************************
  Ŀ¼����
*********************************************************************************************************/

#ifndef CLFS_READONLY
/* ˵��: ����Ŀ¼ */
// ʧ��ʱ���ظ�������롣
int clfs_mkdir(clfs_t *clfs, const char *path);
#endif

/* ˵��: ��Ŀ¼ */
// ʧ��ʱ���ظ�������롣
int clfs_dir_open(clfs_t *clfs, clfs_dir_t *dir, const char *path);

/* ˵��: �ر�Ŀ¼���ͷ��κ��ѷ������Դ */
int clfs_dir_close(clfs_t *clfs, clfs_dir_t *dir);

/* ˵��: ��Ŀ¼���һ����Ŀ */
// ����ָ�����ļ���Ŀ¼��д��Ϣ�ṹ���ɹ�ʱ������ֵ��Ŀ¼ĩβ����0�������ʱ�ĸ�������롣
int clfs_dir_read(clfs_t *clfs, clfs_dir_t *dir, struct clfs_info *info);

/* ˵��: �ı�Ŀ¼��λ�� */
// �µ�off�����Ǵ�tell���ص���һ��ֵ����ָ��Ŀ¼�����еľ���ƫ������
// ʧ��ʱ���ظ�������롣
int clfs_dir_seek(clfs_t *clfs, clfs_dir_t *dir, clfs_off_t off);

/* ˵��: ����Ŀ¼��λ�� */
// ���ص�ƫ����������seek�������޷����ɣ���ȷʵָʾĿ¼�����еĵ�ǰλ�á�
// ����Ŀ¼��λ�ã���ʧ��ʱ���ظ�������롣
clfs_soff_t clfs_dir_tell(clfs_t *clfs, clfs_dir_t *dir);

/* ˵��: ��Ŀ¼��λ�ø���ΪĿ¼�Ŀ�ͷ */
// ʧ��ʱ���ظ�������롣
int clfs_dir_rewind(clfs_t *clfs, clfs_dir_t *dir);


/*********************************************************************************************************
  �ļ�ϵͳ����
*********************************************************************************************************/

/* ˵��: �ļ�ϵͳ�ĵ�ǰ��С */
// ����ļ�����COW�ṹ���򷵻�С���ܴ����ļ�ϵͳ��ʵ�ʴ�С��
// ���ط���Ŀ�������ʧ��ʱ���ظ�������롣
clfs_ssize_t clfs_fs_size(clfs_t *clfs);

/* ˵��: �����ļ�ϵͳ����ʹ�õ����п� */
// ���ṩ�Ļص������ļ�ϵͳ��ǰʹ�õ�ÿ�����ַ���ã����������ȷ����Щ������ʹ�ã������ж��ٴ洢����
int clfs_fs_traverse(clfs_t *clfs, int (*cb)(void*, clfs_block_t), void *data);

#ifndef CLFS_READONLY
#ifdef CLFS_MIGRATE

/* ˵��������Ǩ��֮ǰ�汾��clfs */
int clfs_migrate(clfs_t *clfs, const struct clfs_config *cfg);

#endif
#endif


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
