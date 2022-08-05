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
** 文   件   名: lfs_port.h
**
** 创   建   人: 章俊文
**
** 文件创建日期: 2022 年 06 月 04 日
**
** 描        述: LittleFs与VFS的接口文件
*********************************************************************************************************/
#define  __SYLIXOS_STDIO
#define  __SYLIXOS_KERNEL

#ifndef __LFS_PORT_H
#define __LFS_PORT_H

#include"lfs.h"
#include "../../driver/mtd/nor/nor.h"
#include "SylixOS.h"
#include "../SylixOS/kernel/include/k_kernel.h"
#include "../SylixOS/system/include/s_system.h"
#include "../SylixOS/fs/fsCommon/fsCommon.h"
#include "../SylixOS/fs/include/fs_fs.h"


/*********************************************************************************************************
  ???
*********************************************************************************************************/
#if LW_CFG_MAX_VOLUMES > 0 //&& LW_CFG_LFS_EN > 0

/*********************************************************************************************************
                                             相关外部API
*********************************************************************************************************/
LW_API INT      API_LittleFsDrvInstall(VOID);
LW_API INT      API_LittleFsDevCreate (PCHAR  pcName, PLW_BLK_DEV pblkd);
LW_API INT      API_LittleFsDevDelete (PCHAR  pcName);

#define littlefsDrv                API_LittleFsDrvInstall
#define littlefsDevCreate          API_LittleFsDevCreate
#define littlefsDevDelete          API_LittleFsDevDelete

static LONG     __littleFsOpen();
static INT      __littleFsRemove();
static INT      __littleFsClose();
static ssize_t  __littleFsRead();
static ssize_t  __littleFsPRead();
static ssize_t  __littleFsWrite();
static ssize_t  __littleFsPWrite();
static INT      __littleFsStat();
static INT      __littleFsIoctl();
static INT      __littleFsSymlink();
static ssize_t  __littleFsReadlink();
static INT      __littleFsLStat();

/**********************************************************************************************************
*                                           LFS相关结构体                                                  *
***********************************************************************************************************/

/* 为了匹配SylixOS，对lfs_t又做了一层封装，加入了VFS需要的信息 */
typedef struct lfs_volume{
    LW_DEV_HDR          LFS_devhdrHdr;                                /*  lfs文件系统设备头        */
    LW_OBJECT_HANDLE    LFS_hVolLock;                                 /*  卷操作锁                 */
    LW_LIST_LINE_HEADER LFS_plineFdNodeHeader;                        /*  fd_node 链表             */

    BOOL                LFS_bForceDelete;                             /*  是否允许强制卸载卷        */
    BOOL                LFS_bValid;

    uid_t               LFS_uid;                                      /*  用户 id                  */
    gid_t               LFS_gid;                                      /*  组   id                  */
    mode_t              LFS_mode;                                     /*  文件 mode                */
    time_t              LFS_time;                                     /*  创建时间                  */
    lfs_t               lfst;                                         /*  lfs文件系统句柄           */
} LFS_VOLUME;
typedef LFS_VOLUME*     PLFS_VOLUME;

/* 为了匹配SylixOS，将dir和file类型封装为node文件节点，并加入了文件共享信息 */
typedef struct lfs_node {
    PLFS_VOLUME         LFSN_plfs;                                      /*       文件系统               */

    BOOL                LFSN_bChanged;                                  /*       文件内容是否更改          */
    mode_t              LFSN_mode;                                      /*       文件 mode              */
    time_t              LFSN_timeCreate;                                /*       创建时间                        */
    time_t              LFSN_timeAccess;                                /*       最后访问时间                 */
    time_t              LFSN_timeChange;                                /*       最后修改时间                 */

    size_t              LFSN_stSize;                                    /*  当前文件大小 (可能大于缓冲) */
    size_t              LFSN_stVSize;                                   /*      lseek 出的虚拟大小        */

    uid_t               LFSN_uid;                                       /*         用户 id            */
    gid_t               LFSN_gid;                                       /*         组   id             */
    
    /* 有两种类型，根据isfile判断，lfsdir和lfsfile其中一个为空 */
    PCHAR               LFSN_pcLink;                                    /*         链接目标              */
    bool                isfile;
    lfs_dir_t           lfsdir;
    lfs_file_t          lfsfile;
} LFS_NODE;
typedef LFS_NODE*       PLFS_NODE;

/**********************************************************************************************************
*                                           LFS与Sylix转换函数                                             *
***********************************************************************************************************/

static int genSylixMode(int lfsType, int lfsFlag){
    int temp = 0;
    if (lfsFlag & LFS_O_RDONLY)    temp |= O_RDONLY;
    if (lfsFlag & LFS_O_WRONLY)    temp |= O_WRONLY;
    if (lfsFlag & LFS_O_RDWR)      temp |= O_RDWR;

    if (lfsType & LFS_TYPE_REG)   temp |= S_IFREG;
    if (lfsType & LFS_TYPE_DIR)   temp |= S_IFDIR;
    if (lfsType & LFS_TYPE_SLINK) temp |= S_IFLNK;
    return temp;
}

static int genSylixFlag(int lfsFlag){
    int temp = 0;
    if (lfsFlag & LFS_O_CREAT)     temp |= O_CREAT;
    if (lfsFlag & LFS_O_EXCL)      temp |= O_EXCL;
    if (lfsFlag & LFS_O_TRUNC)     temp |= O_TRUNC;
    if (lfsFlag & LFS_O_APPEND)    temp |= O_APPEND; 
    return temp;
}

static int genLfsFlag(int sylixMode, int sylixFlag){
    int temp = 0;
    if (sylixFlag & O_CREAT)     temp |= LFS_O_CREAT;
    if (sylixFlag & O_EXCL)      temp |= LFS_O_EXCL;
    if (sylixFlag & O_TRUNC)     temp |= LFS_O_TRUNC;
    if (sylixFlag & O_APPEND)    temp |= LFS_O_APPEND; 

    if (sylixMode & O_WRONLY)    temp |= LFS_O_WRONLY;
    if (sylixMode & O_RDWR)      temp |= LFS_O_RDWR;
    if ( !(sylixMode & O_WRONLY) && !(sylixMode & O_RDWR))
        temp |= LFS_O_RDONLY;
    return temp;
}

static int genLfsType(int sylixMode){
    int temp = 0;
    if (sylixMode & S_IFREG)   temp |= LFS_TYPE_REG;
    if (sylixMode & S_IFDIR)   temp |= LFS_TYPE_DIR;
    if (sylixMode & S_IFLNK)   temp |= LFS_TYPE_SLINK;
    return temp;
}


/**********************************************************************************************************
*                                              常用的宏定义                                                *
***********************************************************************************************************/

#define __LFS_FILE_LOCK(plfsn)        API_SemaphoreMPend(plfsn->LFSN_plfs->LFS_hVolLock, \
                                      LW_OPTION_WAIT_INFINITE)
#define __LFS_FILE_UNLOCK(plfsn)      API_SemaphoreMPost(plfsn->LFSN_plfs->LFS_hVolLock)
#define __LFS_VOL_LOCK(pfs)           API_SemaphoreMPend(pfs->LFS_hVolLock, \
                                      LW_OPTION_WAIT_INFINITE)
#define __LFS_VOL_UNLOCK(pfs)         API_SemaphoreMPost(pfs->LFS_hVolLock)
#define __STR_IS_ROOT(pcName)         ((pcName[0] == PX_EOS) || (lib_strcmp(PX_STR_ROOT, pcName) == 0))


/**********************************************************************************************************
*                                           内部全局变量/常量                                              *
***********************************************************************************************************/
const static INT BEGIN_OFF_AM29LV160DB   = 256*1024;
static       INT _G_iLittleFsDrvNum      = PX_ERROR;


/**********************************************************************************************************
*                                             底层驱动函数                                                 *
***********************************************************************************************************/

/* lfs与底层flash读数据接口
 * @palfs  c      文件系统配置结构体
 * @palfs  block  块编号
 * @palfs  off    块内偏移地址
 * @palfs  buffer 用于存储读取到的数据
 * @palfs  size   要读取的字节数
 * @return                        */
static int lfs_mini2440_read(const struct lfs_config *c, lfs_block_t block, 
                            lfs_off_t off, void *buffer, lfs_size_t size)
{
    int error = read_nor(c->block_size * block + off + BEGIN_OFF_AM29LV160DB, (PCHAR)buffer, size);
    return error;
}

/* lfs与底层flash写数据接口
 * @palfs  c      文件系统配置结构体
 * @palfs  block  块编号
 * @palfs  off    块内偏移地址
 * @palfs  buffer 待写入的数据
 * @palfs  size   待写入数据的大小
 * @return                        */
static int lfs_mini2440_prog(const struct lfs_config *c, lfs_block_t block, 
                            lfs_off_t off, const void *buffer, lfs_size_t size)
{
    int error = write_nor(c->block_size * block + off + BEGIN_OFF_AM29LV160DB, (PCHAR)buffer, size, WRITE_KEEP);
    return error;
}

/* lfs与底层flash擦除接口
 * @palfs  c     文件系统配置结构体
 * @palfs  block 块编号
 * @return       错误编号         */
static int lfs_mini2440_erase(const struct lfs_config *c, lfs_block_t block)
{
    int error = erase_nor(c->block_size * block + BEGIN_OFF_AM29LV160DB, ERASE_SECTOR);
    return error;
}

/* lfs与底层flash同步接口
 * @palfs  c     文件系统配置结构体
 * @return       错误编号         */
static int lfs_mini2440_sync(const struct lfs_config *c)
{
    return LFS_ERR_OK;
}

/**********************************************************************************************************
*                                      文件系统默认初始化配置，重要！！！                                    *
***********************************************************************************************************/

static const struct lfs_config cfg =
{
    .read  = lfs_mini2440_read,
    .prog  = lfs_mini2440_prog,
    .erase = lfs_mini2440_erase,
    .sync  = lfs_mini2440_sync,

    .read_size = 4,
    .prog_size = 4,
    .block_size = 64 * 1024,
    .block_count = 28,
    .cache_size = 256,
    .lookahead_size = 16,
    .block_cycles = 500,
};

/*********************************************************************************************************
** 函数名称: __little_stat
** 功能描述: lfs 获得文件 stat
** 输　入  : plfsn           文件节点
**           plfs           文件系统
**           pstat          获得的 stat
** 输　出  : 创建结果
** 全局变量:
** 调用模块:
*********************************************************************************************************/
static inline void __lfs_init_plfsn(PLFS_NODE  plfsn, 
                                    PLFS_VOLUME  plfs,
                                    mode_t iMode){
    plfsn->LFSN_plfs         = plfs;
    plfsn->LFSN_bChanged     = false;
    plfsn->LFSN_mode         = iMode;
    plfsn->LFSN_timeAccess   = lib_time(LW_NULL);
    plfsn->LFSN_timeChange   = lib_time(LW_NULL);
    plfsn->LFSN_timeCreate   = lib_time(LW_NULL);
    plfsn->LFSN_uid          = getuid();
    plfsn->LFSN_gid          = getgid(); 
    if(plfsn->isfile){
        plfsn->LFSN_stSize   = lfs_file_size(&plfs->lfst,&plfsn->lfsfile);
    }else{
        plfsn->LFSN_stSize   = 0;
    }
    plfsn->LFSN_stVSize      = plfsn->LFSN_stSize;
}
/*********************************************************************************************************
** 函数名称: __little_stat
** 功能描述: lfs 获得文件 stat
** 输　入  : plfsn           文件节点
**           plfs           文件系统
**           pstat          获得的 stat
** 输　出  : 创建结果
** 全局变量:
** 调用模块:
*********************************************************************************************************/
static inline void __lfs_stat (PLFS_NODE  plfsn, 
                               PLFS_VOLUME  plfs, 
                               struct stat  *pstat)
{
    if (plfsn) {
        pstat->st_dev     = LW_DEV_MAKE_STDEV(&plfs->LFS_devhdrHdr);
        pstat->st_ino     = (ino_t)plfsn;
        pstat->st_mode    = plfsn->LFSN_mode;
        pstat->st_nlink   = 1;
        pstat->st_uid     = plfsn->LFSN_uid;
        pstat->st_gid     = plfsn->LFSN_gid;
        pstat->st_rdev    = 1;
        pstat->st_size    = (off_t)plfsn->LFSN_stSize;
        pstat->st_atime   = plfsn->LFSN_timeAccess;
        pstat->st_mtime   = plfsn->LFSN_timeChange;
        pstat->st_ctime   = plfsn->LFSN_timeCreate;

    } else {
        pstat->st_dev     = LW_DEV_MAKE_STDEV(&plfs->LFS_devhdrHdr);
        pstat->st_ino     = (ino_t)0;
        pstat->st_mode    = plfs->LFS_mode;
        pstat->st_nlink   = 1;
        pstat->st_uid     = plfs->LFS_uid;
        pstat->st_gid     = plfs->LFS_gid;
        pstat->st_rdev    = 1;
        pstat->st_size    = 0;
        pstat->st_atime   = plfs->LFS_time;
        pstat->st_mtime   = plfs->LFS_time;
        pstat->st_ctime   = plfs->LFS_time;
        pstat->st_blocks  = 0;
    }
    pstat->st_resv1 = LW_NULL;
    pstat->st_resv2 = LW_NULL;
    pstat->st_resv3 = LW_NULL;
}

/*********************************************************************************************************
** 函数名称: __little_statfs
** 功能描述: lfs 获得文件 stat
** 输　入  : pfs           文件系统
**           pstatfs          获得的 statfs
** 输　出  : 创建结果
** 全局变量:
** 调用模块:
*********************************************************************************************************/
static inline void  __lfs_statfs (PLFS_VOLUME  pfs, 
                                  struct statfs  *pstatfs)
{
    pstatfs->f_type   = TMPFS_MAGIC;
    pstatfs->f_bavail = 1;

    pstatfs->f_files  = 0;
    pstatfs->f_ffree  = 0;

#if LW_CFG_CPU_WORD_LENGHT == 64
    pstatfs->f_fsid.val[0] = (int32_t)((addr_t)pfs >> 32);
    pstatfs->f_fsid.val[1] = (int32_t)((addr_t)pfs & 0xffffffff);
#else
    pstatfs->f_fsid.val[0] = (int32_t)pfs;
    pstatfs->f_fsid.val[1] = 0;
#endif

    pstatfs->f_flag    = 0;
    pstatfs->f_namelen = PATH_MAX;
}

/* 创建节点，并打开，信息保存在plfsn中返回 */
static inline PLFS_NODE __lfs_maken (PLFS_VOLUME plfs,
                                     PCHAR       pcName,
                                     mode_t      mode,
                                     PCHAR       pcLink)
{
    int err = 0;

    PLFS_NODE plfsn = (PLFS_NODE)__SHEAP_ALLOC(sizeof(LFS_NODE)); /*    申请内存，创建节点       */
    // printf("__lfs_maken(): PLFS_NODE plfsn = (PLFS_NODE)__SHEAP_ALLOC(sizeof(LFS_NODE));\r\n");
    if (plfsn == LW_NULL){
        _ErrorHandle(ENOMEM);
        return  (NULL);
    }
    lib_bzero(plfsn,sizeof(LFS_NODE));                            /*       节点清空          */

    if (S_ISLNK(mode)){                                           /*     创建操作(链接)      */
        err = lfs_file_open(&plfs->lfst, &plfsn->lfsfile, pcName,
                genLfsFlag(mode, 0)|LFS_O_CREAT);
        if(err >= 0){
            // printf("__lfs_maken(): SLINK open success!\r\n");
            __lfs_init_plfsn(plfsn, plfs, mode|S_IFLNK);
            plfsn->isfile = true;
            err = lfs_setattr(&plfs->lfst, pcName, LFS_TYPE_SLINK, 
                              pcLink, lib_strlen(pcLink));
            if(err >= 0) {
                // printf("lfs_setattr() success!\r\n");
                plfsn->LFSN_pcLink = (PCHAR)__SHEAP_ALLOC(lib_strlen(pcLink)+1);
                // printf("%%% __lfs_maken(): plfsn->LFSN_pcLink = (PCHAR)__SHEAP_ALLOC(lib_strlen(pcLink)+1);\r\n");
                // printf("size: %d , p: %p \r\n",lib_strlen(pcLink)+1, plfsn->LFSN_pcLink);
                if(plfsn->LFSN_pcLink == LW_NULL){
                    __SHEAP_FREE(plfsn);
                    _ErrorHandle(ENOMEM);
                    return (LW_NULL);
                }
                lib_strncpy(plfsn->LFSN_pcLink, pcLink, lib_strlen(pcLink)+1);
            }
            // else printf("lfs_setattr() failed!\r\n");
//            lfs_file_close(&plfs->lfst, &plfsn->lfsfile);
        }else{
            // printf("__lfs_maken(): SLINK open failed!\r\n");
        }
    } else if (S_ISDIR(mode)){
        err = lfs_mkdir(&plfs->lfst, pcName);                     /*     创建操作(目录)      */
        if(err >= 0) {
            //  printf("__lfs_maken(): lfs_mkdir sucess!\r\n");
            err = lfs_dir_open(&plfs->lfst, &plfsn->lfsdir, pcName);
            if(err >= 0){
                //  printf("__lfs_maken(): lfs_dir_open sucess!\r\n");
                __lfs_init_plfsn(plfsn, plfs, mode|S_IFDIR);
                plfsn->isfile = false;
                plfsn->LFSN_pcLink = LW_NULL;
            }
            lfs_dir_close(&plfs->lfst, &plfsn->lfsdir);
        }
    } else {                                                      /*     创建操作(文件)      */
        err = lfs_file_open(&plfs->lfst, &plfsn->lfsfile, pcName,
                genLfsFlag(mode, 0)|LFS_O_CREAT);
        if(err >= 0){
            //  printf("__lfs_maken(): lfs_file_open with create sucess!\r\n");
            __lfs_init_plfsn(plfsn, plfs, mode|S_IFREG);
            plfsn->isfile = true;
            plfsn->LFSN_pcLink = LW_NULL;
//            lfs_file_close(&plfs->lfst, &plfsn->lfsfile);
        }
    }

    if (err < 0) {
        __SHEAP_FREE(plfsn);
        //  printf("__lfs_maken(): failed ! \r\n");
        return LW_NULL;
    }
    return  plfsn;
}

/* 单纯的打开文件或目录，若节点不存在不会创建节点 */
static inline PLFS_NODE __lfs_open (PLFS_VOLUME pfs,
                                    PCHAR       pcName,
                                    INT         iFlags,
                                    INT         iMode,
                                    BOOL*       broot)
{
    int err = 0;
    CHAR pcLink[256];

    /* 首先判断是否是文件系统根目录 */
    *broot = FALSE;
    if (*pcName == PX_ROOT) {                                     /*       忽略根符号       */
        if (pcName[1] == PX_EOS) *broot= TRUE;
        else *broot = FALSE;
    } else {
        if (pcName[0] == PX_EOS) *broot= TRUE;
        else *broot = FALSE;
    }

    if (iFlags & O_CREAT){
        //  printf("in func(__lfs_open), node can't be made.\r\n");
        return (NULL);
    }

    PLFS_NODE plfsn = (PLFS_NODE)__SHEAP_ALLOC(sizeof(LFS_NODE));         /*  申请内存，创建节点    */
    // printf("__lfs_open(): PLFS_NODE plfsn = (PLFS_NODE)__SHEAP_ALLOC(sizeof(LFS_NODE));\r\n");
    if (plfsn == LW_NULL){
        _ErrorHandle(ENOMEM);
        return  (NULL);
    }
    lib_bzero(plfsn,sizeof(LFS_NODE));                                    /*     节点清空             */
    
    /* 这里不用iMode判断文件还是目录，是因为有时信息未读取，iMode未知。*/
    err = lfs_file_open(&pfs->lfst, &plfsn->lfsfile,             //TODO
                                pcName, genLfsFlag(iMode, iFlags));
    if(err >= 0){
        plfsn->isfile = true;
        int getattr = lfs_getattr(&pfs->lfst, pcName, LFS_TYPE_SLINK,
                                  (PCHAR)pcLink, 256);
        if(getattr < 0){                                                 /*    单纯的文件类型      */
            __lfs_init_plfsn(plfsn, pfs, iMode|S_IFREG);
            plfsn->LFSN_pcLink = LW_NULL;
            printf("lfs_file_open() success, type is file!\r\n");
        }else{                                                           /*    链接文件类型         */
            __lfs_init_plfsn(plfsn, pfs, iMode|S_IFLNK);
            plfsn->LFSN_pcLink = (PCHAR)__SHEAP_ALLOC(getattr+1);
            // printf("%%% __lfs_open(): plfsn->LFSN_pcLink = (PCHAR)__SHEAP_ALLOC(getattr+1);\r\n");
            // printf("size: %d , p: %p \r\n",getattr+1, plfsn->LFSN_pcLink);
            lib_strncpy(plfsn->LFSN_pcLink, (PCHAR)pcLink, getattr+1);
            printf("lfs_file_open() success, type is link!\r\n");
        } 
    }else{                                                               /*    目录文件类型         */
        err = lfs_dir_open(&pfs->lfst, &plfsn->lfsdir, pcName);
        if(err >= 0){   
            plfsn->isfile = false;
            plfsn->LFSN_pcLink = LW_NULL;
            __lfs_init_plfsn(plfsn, pfs, iMode|S_IFDIR);
             printf("lfs_dir_open() success, type is dir!\r\n");
        }
    }

    if (err < 0) {
        __SHEAP_FREE(plfsn);
         printf("_lfs_open() failed!\r\n\r\n");
        return NULL;
    }

    // printf("_lfs_open() end, plfsn: %p  %d !\r\n\r\n",plfsn,(int)plfsn);
    return plfsn;
}

/* 删除一个文件或文件夹节点 */
static inline INT  __lfs_unlink (PLFS_NODE  plfsn)
{
    PLFS_VOLUME     plfs = plfsn->LFSN_plfs;
    
    if (plfsn!=NULL && plfsn!=PX_ERROR && S_ISDIR(plfsn->LFSN_mode)) {          /* 判断目录不为空 */                               /*    文件夹若要删除，必须为空    */
        lfs_dir_rewind(&plfs->lfst, &plfsn->lfsdir);
        struct lfs_info infotemp;
        int err = lfs_dir_read(&plfs->lfst, &plfsn->lfsdir, &infotemp);
        if(err > 0) {
             printf("__lfs_unlink(): the dir is not empty, and can't move!\r\n");
            return (PX_ERROR);
        }else{
             printf("__lfs_unlink: dir remove success!\r\n");
        }
    }
    if(plfsn->LFSN_pcLink != LW_NULL){
        // printf("*** __lfs_unlink(): __SHEAP_FREE(plfsn->LFSN_pcLink); p: %p",plfsn->LFSN_pcLink);
        __SHEAP_FREE(plfsn->LFSN_pcLink);

    }
    __SHEAP_FREE(plfsn);
    // printf("NNNNNDDDDD __lfs_unlink(): __SHEAP_FREE(plfsn);\r\n");
    printf("__lfs_unlink() end!\r\n\r\n");
    return  (ERROR_NONE);
}

#endif


#endif //__LFS_PORT_H
