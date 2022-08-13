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
** 文   件   名: clfs_port.h
**
** 创   建   人: 章俊文
**
** 文件创建日期: 2022 年 06 月 04 日
**
** 描        述: ClFs与VFS的接口文件
*********************************************************************************************************/
#define  __SYLIXOS_STDIO
#define  __SYLIXOS_KERNEL

#ifndef __CLFS_PORT_H
#define __CLFS_PORT_H

#include"clfs.h"
#include "../../driver/mtd/nor/nor.h"
#include "SylixOS.h"
#include "../SylixOS/kernel/include/k_kernel.h"
#include "../SylixOS/system/include/s_system.h"
#include "../SylixOS/fs/fsCommon/fsCommon.h"
#include "../SylixOS/fs/include/fs_fs.h"


/*********************************************************************************************************
  ???
*********************************************************************************************************/
#if LW_CFG_MAX_VOLUMES > 0 //&& LW_CFG_CLFS_EN > 0

/*********************************************************************************************************
                                             相关外部API
*********************************************************************************************************/
LW_API INT      API_ClFsDrvInstall(VOID);
LW_API INT      API_ClFsDevCreate (PCHAR  pcName, PLW_BLK_DEV pblkd);
LW_API INT      API_ClFsDevDelete (PCHAR  pcName);

#define clfsDrv                API_ClFsDrvInstall
#define clfsDevCreate          API_ClFsDevCreate
#define clfsDevDelete          API_ClFsDevDelete

static LONG     __clFsOpen();
static INT      __clFsRemove();
static INT      __clFsClose();
static ssize_t  __clFsRead();
static ssize_t  __clFsPRead();
static ssize_t  __clFsWrite();
static ssize_t  __clFsPWrite();
static INT      __clFsStat();
static INT      __clFsIoctl();
static INT      __clFsSymlink();
static ssize_t  __clFsReadlink();
static INT      __clFsLStat();

/**********************************************************************************************************
*                                           CLFS相关结构体                                                  *
***********************************************************************************************************/

/* 为了匹配SylixOS，对clfs_t又做了一层封装，加入了VFS需要的信息 */
typedef struct clfs_volume{
    LW_DEV_HDR          CLFS_devhdrHdr;                                /*  clfs文件系统设备头        */
    LW_OBJECT_HANDLE    CLFS_hVolLock;                                 /*  卷操作锁                 */
    LW_LIST_LINE_HEADER CLFS_plineFdNodeHeader;                        /*  fd_node 链表             */

    BOOL                CLFS_bForceDelete;                             /*  是否允许强制卸载卷        */
    BOOL                CLFS_bValid;

    uid_t               CLFS_uid;                                      /*  用户 id                  */
    gid_t               CLFS_gid;                                      /*  组   id                  */
    mode_t              CLFS_mode;                                     /*  文件 mode                */
    time_t              CLFS_time;                                     /*  创建时间                  */
    clfs_t               clfst;                                         /*  clfs文件系统句柄           */
} CLFS_VOLUME;
typedef CLFS_VOLUME*     PCLFS_VOLUME;

/* 为了匹配SylixOS，将dir和file类型封装为node文件节点，并加入了文件共享信息 */
typedef struct clfs_node {
    PCLFS_VOLUME         CLFSN_pclfs;                                      /*       文件系统               */

    BOOL                CLFSN_bChanged;                                  /*       文件内容是否更改          */
    mode_t              CLFSN_mode;                                      /*       文件 mode              */
    time_t              CLFSN_timeCreate;                                /*       创建时间                        */
    time_t              CLFSN_timeAccess;                                /*       最后访问时间                 */
    time_t              CLFSN_timeChange;                                /*       最后修改时间                 */

    size_t              CLFSN_stSize;                                    /*  当前文件大小 (可能大于缓冲) */
    size_t              CLFSN_stVSize;                                   /*      lseek 出的虚拟大小        */

    uid_t               CLFSN_uid;                                       /*         用户 id            */
    gid_t               CLFSN_gid;                                       /*         组   id             */
    
    /* 有两种类型，根据isfile判断，clfsdir和clfsfile其中一个为空 */
    PCHAR               CLFSN_pcLink;                                    /*         链接目标              */
    bool                isfile;
    clfs_dir_t           clfsdir;
    clfs_file_t          clfsfile;
} CLFS_NODE;
typedef CLFS_NODE*       PCLFS_NODE;

/**********************************************************************************************************
*                                           CLFS与Sylix转换函数                                             *
***********************************************************************************************************/

static int genSylixMode(int clfsType, int clfsFlag){
    int temp = 0;
    if (clfsFlag & CLFS_O_RDONLY)    temp |= O_RDONLY;
    if (clfsFlag & CLFS_O_WRONLY)    temp |= O_WRONLY;
    if (clfsFlag & CLFS_O_RDWR)      temp |= O_RDWR;

    if (clfsType & CLFS_TYPE_REG)   temp |= S_IFREG;
    if (clfsType & CLFS_TYPE_DIR)   temp |= S_IFDIR;
    if (clfsType & CLFS_TYPE_SLINK) temp |= S_IFLNK;
    return temp;
}

static int genSylixFlag(int clfsFlag){
    int temp = 0;
    if (clfsFlag & CLFS_O_CREAT)     temp |= O_CREAT;
    if (clfsFlag & CLFS_O_EXCL)      temp |= O_EXCL;
    if (clfsFlag & CLFS_O_TRUNC)     temp |= O_TRUNC;
    if (clfsFlag & CLFS_O_APPEND)    temp |= O_APPEND; 
    return temp;
}

static int genClfsFlag(int sylixMode, int sylixFlag){
    int temp = 0;
    if (sylixFlag & O_CREAT)     temp |= CLFS_O_CREAT;
    if (sylixFlag & O_EXCL)      temp |= CLFS_O_EXCL;
    if (sylixFlag & O_TRUNC)     temp |= CLFS_O_TRUNC;
    if (sylixFlag & O_APPEND)    temp |= CLFS_O_APPEND; 

    if (sylixMode & O_WRONLY)    temp |= CLFS_O_WRONLY;
    if (sylixMode & O_RDWR)      temp |= CLFS_O_RDWR;
    if ( !(sylixMode & O_WRONLY) && !(sylixMode & O_RDWR))
        temp |= CLFS_O_RDONLY;
    return temp;
}

static int genClfsType(int sylixMode){
    int temp = 0;
    if (sylixMode & S_IFREG)   temp |= CLFS_TYPE_REG;
    if (sylixMode & S_IFDIR)   temp |= CLFS_TYPE_DIR;
    if (sylixMode & S_IFLNK)   temp |= CLFS_TYPE_SLINK;
    return temp;
}


/**********************************************************************************************************
*                                              常用的宏定义                                                *
***********************************************************************************************************/

#define __CLFS_FILE_LOCK(pclfsn)        API_SemaphoreMPend(pclfsn->CLFSN_pclfs->CLFS_hVolLock, \
                                      LW_OPTION_WAIT_INFINITE)
#define __CLFS_FILE_UNLOCK(pclfsn)      API_SemaphoreMPost(pclfsn->CLFSN_pclfs->CLFS_hVolLock)
#define __CLFS_VOL_LOCK(pfs)           API_SemaphoreMPend(pfs->CLFS_hVolLock, \
                                      LW_OPTION_WAIT_INFINITE)
#define __CLFS_VOL_UNLOCK(pfs)         API_SemaphoreMPost(pfs->CLFS_hVolLock)
#define __STR_IS_ROOT(pcName)         ((pcName[0] == PX_EOS) || (lib_strcmp(PX_STR_ROOT, pcName) == 0))


/**********************************************************************************************************
*                                           内部全局变量/常量                                              *
***********************************************************************************************************/
const static INT BEGIN_OFF_AM29LV160DB   = 256*1024;
static       INT _G_iClFsDrvNum      = PX_ERROR;


/**********************************************************************************************************
*                                             底层驱动函数                                                 *
***********************************************************************************************************/

/* clfs与底层flash读数据接口
 * @paclfs  c      文件系统配置结构体
 * @paclfs  block  块编号
 * @paclfs  off    块内偏移地址
 * @paclfs  buffer 用于存储读取到的数据
 * @paclfs  size   要读取的字节数
 * @return                        */
static int clfs_mini2440_read(const struct clfs_config *c, clfs_block_t block, 
                            clfs_off_t off, void *buffer, clfs_size_t size)
{
    int error = read_nor(c->block_size * block + off + BEGIN_OFF_AM29LV160DB, (PCHAR)buffer, size);
    return error;
}

/* clfs与底层flash写数据接口
 * @paclfs  c      文件系统配置结构体
 * @paclfs  block  块编号
 * @paclfs  off    块内偏移地址
 * @paclfs  buffer 待写入的数据
 * @paclfs  size   待写入数据的大小
 * @return                        */
static int clfs_mini2440_prog(const struct clfs_config *c, clfs_block_t block, 
                            clfs_off_t off, const void *buffer, clfs_size_t size)
{
    int error = write_nor(c->block_size * block + off + BEGIN_OFF_AM29LV160DB, (PCHAR)buffer, size, WRITE_KEEP);
    return error;
}

/* clfs与底层flash擦除接口
 * @paclfs  c     文件系统配置结构体
 * @paclfs  block 块编号
 * @return       错误编号         */
static int clfs_mini2440_erase(const struct clfs_config *c, clfs_block_t block)
{
    int error = erase_nor(c->block_size * block + BEGIN_OFF_AM29LV160DB, ERASE_SECTOR);
    return error;
}

/* clfs与底层flash同步接口
 * @paclfs  c     文件系统配置结构体
 * @return       错误编号         */
static int clfs_mini2440_sync(const struct clfs_config *c)
{
    return CLFS_ERR_OK;
}

/**********************************************************************************************************
*                                      文件系统默认初始化配置，重要！！！                                    *
***********************************************************************************************************/

static const struct clfs_config cfg =
{
    .read  = clfs_mini2440_read,
    .prog  = clfs_mini2440_prog,
    .erase = clfs_mini2440_erase,
    .sync  = clfs_mini2440_sync,

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
** 功能描述: clfs 获得文件 stat
** 输　入  : pclfsn           文件节点
**           pclfs           文件系统
**           pstat          获得的 stat
** 输　出  : 创建结果
** 全局变量:
** 调用模块:
*********************************************************************************************************/
static inline void __clfs_init_pclfsn(PCLFS_NODE  pclfsn, 
                                    PCLFS_VOLUME  pclfs,
                                    mode_t iMode){
    pclfsn->CLFSN_pclfs         = pclfs;
    pclfsn->CLFSN_bChanged     = false;
    pclfsn->CLFSN_mode         = iMode;
    pclfsn->CLFSN_timeAccess   = lib_time(LW_NULL);
    pclfsn->CLFSN_timeChange   = lib_time(LW_NULL);
    pclfsn->CLFSN_timeCreate   = lib_time(LW_NULL);
    pclfsn->CLFSN_uid          = getuid();
    pclfsn->CLFSN_gid          = getgid(); 
    if(pclfsn->isfile){
        pclfsn->CLFSN_stSize   = clfs_file_size(&pclfs->clfst,&pclfsn->clfsfile);
    }else{
        pclfsn->CLFSN_stSize   = 0;
    }
    pclfsn->CLFSN_stVSize      = pclfsn->CLFSN_stSize;
}
/*********************************************************************************************************
** 函数名称: __little_stat
** 功能描述: clfs 获得文件 stat
** 输　入  : pclfsn           文件节点
**           pclfs           文件系统
**           pstat          获得的 stat
** 输　出  : 创建结果
** 全局变量:
** 调用模块:
*********************************************************************************************************/
static inline void __clfs_stat (PCLFS_NODE  pclfsn, 
                               PCLFS_VOLUME  pclfs, 
                               struct stat  *pstat)
{
    if (pclfsn) {
        pstat->st_dev     = LW_DEV_MAKE_STDEV(&pclfs->CLFS_devhdrHdr);
        pstat->st_ino     = (ino_t)pclfsn;
        pstat->st_mode    = pclfsn->CLFSN_mode;
        pstat->st_nlink   = 1;
        pstat->st_uid     = pclfsn->CLFSN_uid;
        pstat->st_gid     = pclfsn->CLFSN_gid;
        pstat->st_rdev    = 1;
        pstat->st_size    = (off_t)pclfsn->CLFSN_stSize;
        pstat->st_atime   = pclfsn->CLFSN_timeAccess;
        pstat->st_mtime   = pclfsn->CLFSN_timeChange;
        pstat->st_ctime   = pclfsn->CLFSN_timeCreate;

    } else {
        pstat->st_dev     = LW_DEV_MAKE_STDEV(&pclfs->CLFS_devhdrHdr);
        pstat->st_ino     = (ino_t)0;
        pstat->st_mode    = pclfs->CLFS_mode;
        pstat->st_nlink   = 1;
        pstat->st_uid     = pclfs->CLFS_uid;
        pstat->st_gid     = pclfs->CLFS_gid;
        pstat->st_rdev    = 1;
        pstat->st_size    = 0;
        pstat->st_atime   = pclfs->CLFS_time;
        pstat->st_mtime   = pclfs->CLFS_time;
        pstat->st_ctime   = pclfs->CLFS_time;
        pstat->st_blocks  = 0;
    }
    pstat->st_resv1 = LW_NULL;
    pstat->st_resv2 = LW_NULL;
    pstat->st_resv3 = LW_NULL;
}

/*********************************************************************************************************
** 函数名称: __little_statfs
** 功能描述: clfs 获得文件 stat
** 输　入  : pfs           文件系统
**           pstatfs          获得的 statfs
** 输　出  : 创建结果
** 全局变量:
** 调用模块:
*********************************************************************************************************/
static inline void  __clfs_statfs (PCLFS_VOLUME  pfs, 
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

/* 创建节点，并打开，信息保存在pclfsn中返回 */
static inline PCLFS_NODE __clfs_maken (PCLFS_VOLUME pclfs,
                                     PCHAR       pcName,
                                     mode_t      mode,
                                     PCHAR       pcLink)
{
    int err = 0;

    PCLFS_NODE pclfsn = (PCLFS_NODE)__SHEAP_ALLOC(sizeof(CLFS_NODE)); /*    申请内存，创建节点       */
    // printf("__clfs_maken(): PCLFS_NODE pclfsn = (PCLFS_NODE)__SHEAP_ALLOC(sizeof(CLFS_NODE));\r\n");
    if (pclfsn == LW_NULL){
        _ErrorHandle(ENOMEM);
        return  (NULL);
    }
    lib_bzero(pclfsn,sizeof(CLFS_NODE));                            /*       节点清空          */

    if (S_ISLNK(mode)){                                           /*     创建操作(链接)      */
        err = clfs_file_open(&pclfs->clfst, &pclfsn->clfsfile, pcName,
                genClfsFlag(mode, 0)|CLFS_O_CREAT);
        if(err >= 0){
            // printf("__clfs_maken(): SLINK open success!\r\n");
            __clfs_init_pclfsn(pclfsn, pclfs, mode|S_IFLNK);
            pclfsn->isfile = true;
            err = clfs_setattr(&pclfs->clfst, pcName, CLFS_TYPE_SLINK, 
                              pcLink, lib_strlen(pcLink));
            if(err >= 0) {
                // printf("clfs_setattr() success!\r\n");
                pclfsn->CLFSN_pcLink = (PCHAR)__SHEAP_ALLOC(lib_strlen(pcLink)+1);
                // printf("%%% __clfs_maken(): pclfsn->CLFSN_pcLink = (PCHAR)__SHEAP_ALLOC(lib_strlen(pcLink)+1);\r\n");
                // printf("size: %d , p: %p \r\n",lib_strlen(pcLink)+1, pclfsn->CLFSN_pcLink);
                if(pclfsn->CLFSN_pcLink == LW_NULL){
                    __SHEAP_FREE(pclfsn);
                    _ErrorHandle(ENOMEM);
                    return (LW_NULL);
                }
                lib_strncpy(pclfsn->CLFSN_pcLink, pcLink, lib_strlen(pcLink)+1);
            }
            // else printf("clfs_setattr() failed!\r\n");
//            clfs_file_close(&pclfs->clfst, &pclfsn->clfsfile);
        }else{
            // printf("__clfs_maken(): SLINK open failed!\r\n");
        }
    } else if (S_ISDIR(mode)){
        err = clfs_mkdir(&pclfs->clfst, pcName);                     /*     创建操作(目录)      */
        if(err >= 0) {
            //  printf("__clfs_maken(): clfs_mkdir sucess!\r\n");
            err = clfs_dir_open(&pclfs->clfst, &pclfsn->clfsdir, pcName);
            if(err >= 0){
                //  printf("__clfs_maken(): clfs_dir_open sucess!\r\n");
                __clfs_init_pclfsn(pclfsn, pclfs, mode|S_IFDIR);
                pclfsn->isfile = false;
                pclfsn->CLFSN_pcLink = LW_NULL;
            }
            clfs_dir_close(&pclfs->clfst, &pclfsn->clfsdir);
        }
    } else {                                                      /*     创建操作(文件)      */
        err = clfs_file_open(&pclfs->clfst, &pclfsn->clfsfile, pcName,
                genClfsFlag(mode, 0)|CLFS_O_CREAT);
        if(err >= 0){
            //  printf("__clfs_maken(): clfs_file_open with create sucess!\r\n");
            __clfs_init_pclfsn(pclfsn, pclfs, mode|S_IFREG);
            pclfsn->isfile = true;
            pclfsn->CLFSN_pcLink = LW_NULL;
//            clfs_file_close(&pclfs->clfst, &pclfsn->clfsfile);
        }
    }

    if (err < 0) {
        __SHEAP_FREE(pclfsn);
        //  printf("__clfs_maken(): failed ! \r\n");
        return LW_NULL;
    }
    return  pclfsn;
}

/* 单纯的打开文件或目录，若节点不存在不会创建节点 */
static inline PCLFS_NODE __clfs_open (PCLFS_VOLUME pfs,
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
        //  printf("in func(__clfs_open), node can't be made.\r\n");
        return (NULL);
    }

    PCLFS_NODE pclfsn = (PCLFS_NODE)__SHEAP_ALLOC(sizeof(CLFS_NODE));         /*  申请内存，创建节点    */
    // printf("__clfs_open(): PCLFS_NODE pclfsn = (PCLFS_NODE)__SHEAP_ALLOC(sizeof(CLFS_NODE));\r\n");
    if (pclfsn == LW_NULL){
        _ErrorHandle(ENOMEM);
        return  (NULL);
    }
    lib_bzero(pclfsn,sizeof(CLFS_NODE));                                    /*     节点清空             */
    
    /* 这里不用iMode判断文件还是目录，是因为有时信息未读取，iMode未知。*/
    err = clfs_file_open(&pfs->clfst, &pclfsn->clfsfile,             //TODO
                                pcName, genClfsFlag(iMode, iFlags));
    if(err >= 0){
        pclfsn->isfile = true;
        int getattr = clfs_getattr(&pfs->clfst, pcName, CLFS_TYPE_SLINK,
                                  (PCHAR)pcLink, 256);
        if(getattr < 0){                                                 /*    单纯的文件类型      */
            __clfs_init_pclfsn(pclfsn, pfs, iMode|S_IFREG);
            pclfsn->CLFSN_pcLink = LW_NULL;
            // printf("clfs_file_open() success, type is file!\r\n");
        }else{                                                           /*    链接文件类型         */
            __clfs_init_pclfsn(pclfsn, pfs, iMode|S_IFLNK);
            pclfsn->CLFSN_pcLink = (PCHAR)__SHEAP_ALLOC(getattr+1);
            // printf("%%% __clfs_open(): pclfsn->CLFSN_pcLink = (PCHAR)__SHEAP_ALLOC(getattr+1);\r\n");
            // printf("size: %d , p: %p \r\n",getattr+1, pclfsn->CLFSN_pcLink);
            lib_strncpy(pclfsn->CLFSN_pcLink, (PCHAR)pcLink, getattr+1);
            // printf("clfs_file_open() success, type is link!\r\n");
        } 
    }else{                                                               /*    目录文件类型         */
        err = clfs_dir_open(&pfs->clfst, &pclfsn->clfsdir, pcName);
        if(err >= 0){   
            pclfsn->isfile = false;
            pclfsn->CLFSN_pcLink = LW_NULL;
            __clfs_init_pclfsn(pclfsn, pfs, iMode|S_IFDIR);
            //  printf("clfs_dir_open() success, type is dir!\r\n");
        }
    }

    if (err < 0) {
        __SHEAP_FREE(pclfsn);
        //  printf("_clfs_open() failed!\r\n\r\n");
        return NULL;
    }

    // printf("_clfs_open() end, pclfsn: %p  %d !\r\n\r\n",pclfsn,(int)pclfsn);
    return pclfsn;
}

/* 删除一个文件或文件夹节点 */
static inline INT  __clfs_unlink (PCLFS_NODE  pclfsn)
{
    PCLFS_VOLUME     pclfs = pclfsn->CLFSN_pclfs;
    
    if (pclfsn!=NULL && pclfsn!=PX_ERROR && S_ISDIR(pclfsn->CLFSN_mode)) {          /* 判断目录不为空 */                               /*    文件夹若要删除，必须为空    */
        clfs_dir_rewind(&pclfs->clfst, &pclfsn->clfsdir);
        struct clfs_info infotemp;
        int err = clfs_dir_read(&pclfs->clfst, &pclfsn->clfsdir, &infotemp);
        if(err > 0) {
            //  printf("__clfs_unlink(): the dir is not empty, and can't move!\r\n");
            return (PX_ERROR);
        }else{
            //  printf("__clfs_unlink: dir remove success!\r\n");
        }
    }
    if(pclfsn->CLFSN_pcLink != LW_NULL){
        // printf("*** __clfs_unlink(): __SHEAP_FREE(pclfsn->CLFSN_pcLink); p: %p",pclfsn->CLFSN_pcLink);
        __SHEAP_FREE(pclfsn->CLFSN_pcLink);

    }
    __SHEAP_FREE(pclfsn);
    // printf("NNNNNDDDDD __clfs_unlink(): __SHEAP_FREE(pclfsn);\r\n");
    // printf("__clfs_unlink() end!\r\n\r\n");
    return  (ERROR_NONE);
}

#endif


#endif //__CLFS_PORT_H
