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
** 描        述: lfs向上接口文件
*********************************************************************************************************/
#define  __SYLIXOS_STDIO
#define  __SYLIXOS_KERNEL //加了这两句可以使用已定义的内核函数和结构
#include "lfs.h"
#include "lfs_port.h"
#include "../../driver/mtd/nor/nor.h"
#include "SylixOS.h"
#include "../SylixOS/kernel/include/k_kernel.h"
#include "../SylixOS/system/include/s_system.h"
#include "../SylixOS/fs/fsCommon/fsCommon.h"
#include "../SylixOS/fs/include/fs_fs.h"

#ifndef LITTLEFS_DISABLE


/* 为了匹配SylixOS，对lfs_t又做了一层封装，加入了VFS需要的信息 */
typedef struct lfs_volume{
    LW_DEV_HDR          LFS_devhdrHdr;                                /*  lfs文件系统设备头        */
    LW_OBJECT_HANDLE    LFS_hVolLock;                                 /*  卷操作锁                */
    LW_LIST_LINE_HEADER LFS_plineFdNodeHeader;                        /*  fd_node 链表            */
    LW_LIST_LINE_HEADER LFS_plineSon;                                 /*  儿子链表                */
    BOOL                LFS_bForceDelete;                             /*  是否允许强制卸载卷       */
    BOOL                LFS_bValid;
    uid_t               LFS_uid;                                      /*  用户 id                 */
    gid_t               LFS_gid;                                      /*  组   id                 */
    mode_t              LFS_mode;                                     /*  文件 mode               */
    time_t              LFS_time;                                     /*  创建时间                */
    lfs_t               lfst;                                         /*  lfs文件系统句柄          */
} LFS_VOLUME;
typedef LFS_VOLUME*     PLFS_VOLUME;

/* 为了匹配SylixOS，将dir和file类型封装为node文件节点，并加入了文件共享信息 */
typedef struct lfs_node {
    PLFS_VOLUME         LFSN_plfs;                                      /*       文件系统               */
    BOOL                LFSN_bChanged;                                  /*       文件内容是否更改        */
    mode_t              LFSN_mode;                                      /*       文件 mode              */
    time_t              LFSN_timeCreate;                                /*       创建时间               */
    time_t              LFSN_timeAccess;                                /*       最后访问时间            */
    time_t              LFSN_timeChange;                                /*       最后修改时间            */

    size_t              LFSN_stSize;                                    /*  当前文件大小 (可能大于缓冲)   */
    size_t              LFSN_stVSize;                                   /*      lseek 出的虚拟大小       */
    uid_t               LFSN_uid;                                       /*         用户 id              */
    gid_t               LFSN_gid;                                       /*         组   id              */
    PCHAR               LFSN_pcName;                                    /*         文件名称              */
    PCHAR               LFSN_pcLink;                                    /*         链接目标              */
    /* 有两种类型，根据isfile判断，其中一个指针为空 */
    bool                isfile;
    lfs_dir_t           lfsdir;
    lfs_file_t          lfsfile;
} LFS_NODE;
typedef LFS_NODE*       PLFS_NODE;

#define __LFS_FILE_LOCK(plfsn)        API_SemaphoreMPend(plfsn->LFSN_plfs->LFS_hVolLock, \
                                      LW_OPTION_WAIT_INFINITE)
#define __LFS_FILE_UNLOCK(plfsn)      API_SemaphoreMPost(plfsn->LFSN_plfs->LFS_hVolLock)
#define __LFS_VOL_LOCK(pfs)           API_SemaphoreMPend(pfs->LFS_hVolLock, \
                                      LW_OPTION_WAIT_INFINITE)
#define __LFS_VOL_UNLOCK(pfs)         API_SemaphoreMPost(pfs->LFS_hVolLock)
#define __STR_IS_ROOT(pcName)         ((pcName[0] == PX_EOS) || (lib_strcmp(PX_STR_ROOT, pcName) == 0))

static LONG     __littleFsOpen();
static INT      __littleFsRemove();
static INT      __littleFsClose();
static ssize_t  __littleFsRead();
static ssize_t  __littleFsPRead();
static ssize_t  __littleFsWrite();
static ssize_t  __littleFsPWrite();
static INT      __littleFsStat();
static INT      __littleFsIoctl();
// static INT      __littleFsSymlink();
// static ssize_t  __littleFsReadlink();


/**********************************************************************************************************
*                                     内部全局变量/常量                                                     *
***********************************************************************************************************/
const static INT BEGIN_OFF_AM29LV160DB   = 256*1024;
static       INT _G_iLittleFsDrvNum      = PX_ERROR;


/**********************************************************************************************************
*                                底层驱动函数,文件系统默认配置                                               *
***********************************************************************************************************/

/* lfs与底层flash读数据接口
 * @palfs  c      文件系统配置结构体
 * @palfs  block  块编号
 * @palfs  off    块内偏移地址
 * @palfs  buffer 用于存储读取到的数据
 * @palfs  size   要读取的字节数
 * @return                        */
static int lfs_mini2440_read(const struct lfs_config *c, lfs_block_t block, lfs_off_t off, void *buffer, lfs_size_t size)
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
static int lfs_mini2440_prog(const struct lfs_config *c, lfs_block_t block, lfs_off_t off, const void *buffer, lfs_size_t size)
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

//static uint8_t lfs_read_buf[256];
//static uint8_t lfs_prog_buf[256];
//static uint8_t lfs_lookahead_buf[16];

const struct lfs_config cfg =            /* 文件系统默认初始化配置 */
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
//
//    .read_buffer = lfs_read_buf,
//    .prog_buffer = lfs_prog_buf,
//    .lookahead_buffer = lfs_lookahead_buf
};

static inline void __lfs_init_plfsn(PLFS_NODE  plfsn, PLFS_VOLUME  plfs,mode_t iMode){
    plfsn->LFSN_plfs         = plfs;
    plfsn->LFSN_bChanged     = false;
    plfsn->LFSN_mode         = iMode;
    plfsn->LFSN_timeAccess   = lib_time(LW_NULL);
    plfsn->LFSN_timeChange   = lib_time(LW_NULL);
    plfsn->LFSN_timeCreate   = lib_time(LW_NULL);
    plfsn->LFSN_uid          = getuid();
    plfsn->LFSN_gid          = getgid();
    plfsn->LFSN_pcName       = "hhhh"; 
    plfsn->LFSN_stSize       = 1;
    plfsn->LFSN_stVSize      = 2;
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
static inline void __lfs_stat (PLFS_NODE  plfsn, PLFS_VOLUME  plfs, struct stat  *pstat)
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
static inline void  __lfs_statfs (PLFS_VOLUME  pfs, struct statfs  *pstatfs)
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

static inline int __lfs_maken (PLFS_VOLUME plfs,
                               PCHAR       pcName,
                               PLFS_NODE   plfsn,
                               mode_t      mode)
{
    plfsn = (PLFS_NODE)__SHEAP_ALLOC(sizeof(LFS_NODE));
    if (plfsn == LW_NULL){
        _ErrorHandle(ENOMEM);
        return  (-100);
    }
    lib_bzero(plfsn,sizeof(LFS_NODE));

    if(S_ISDIR(mode)){
        int mkdirerror = lfs_mkdir(&plfs->lfst, pcName);         /*     创建操作(目录)      */
        if(mkdirerror<0){
            printf("dir create failed!\n");
            __SHEAP_FREE(plfsn);
            return (-100);
        }
        else printf("dir create successed!\n");
    }else{                                                      /*     创建操作(文件)      */
        int mkfileerror = lfs_file_open(&plfs->lfst, &plfsn->lfsfile, pcName, 
                                        LFS_TYPE_CREATE|LFS_TYPE_REG);
        if(mkfileerror<0){
            printf("file create failed!\n");
            __SHEAP_FREE(plfsn);
            return (-100);
        }
        else printf("file create successed!\n");
    }

    __lfs_init_plfsn(plfsn, plfs, mode);

    return  (int)plfsn;
}


/*********************************************************************************************************
** 函数名称: __littleOpen
** 功能描述: 打开或者创建文件
** 输　入  :  pfs              内存中littleFs文件系统的super block
**           pcName           文件名
**           iFlags           方式
**           iMode            mode_t
** 输　出  : < 0 错误
** 全局变量:
** 调用模块:
*********************************************************************************************************/
static LONG __littleFsOpen(PLFS_VOLUME     pfs,
    PCHAR           pcName,
    INT             iFlags,
    INT             iMode )
{
    PLW_FD_NODE         pfdnode;
    PLFS_NODE           plfsn;
    struct stat         statGet;
    BOOL                bIsNew;

    if (pcName == LW_NULL) {                                             /*        无文件名              */
        _ErrorHandle(ERROR_IO_NO_DEVICE_NAME_IN_PATH);
        return  (PX_ERROR);
    }

    if (S_ISFIFO(iMode)||S_ISBLK(iMode) ||S_ISCHR(iMode) ||S_ISLNK(iMode)){
        _ErrorHandle(ERROR_IO_DISK_NOT_PRESENT);                         /*     不支持以上这些格式       */
        return  (PX_ERROR);
    }

    if (__LFS_VOL_LOCK(pfs) != ERROR_NONE) {                             /*         设备加锁            */
        _ErrorHandle(ENXIO);                                             
        return  (PX_ERROR);
    }

    if (iFlags & O_CREAT ){
        if (__fsCheckFileName(pcName)) {
            _ErrorHandle(ENOENT);
            return  (PX_ERROR);
        }
        if(__lfs_maken(pfs, pcName, plfsn, iMode) == -100){              /*     创建文件或目录节点       */
            return  (PX_ERROR);
        }
    }       
   
    /************************************ TODO ************************************/
    int openerr = lfs_file_open(&pfs->lfst, &plfsn->lfsfile, pcName, iFlags);
    if(openerr>=0){
        printf("file open success!\n");
        plfsn->isfile = true;
        goto __file_open_ok;
    }else{
        openerr=lfs_dir_open(&pfs->lfst, &plfsn->lfsdir, pcName);
        if(openerr>=0){
            printf("dir open success!\n");
            plfsn->isfile = false;
            iMode = iMode|S_IFDIR;
            goto __file_open_ok;
        }
    }
    printf("open failed!\n");
    return (PX_ERROR);

__file_open_ok:
    __lfs_stat(plfsn, pfs, &statGet);
    pfdnode = API_IosFdNodeAdd(&pfs->LFS_plineFdNodeHeader,
                               statGet.st_dev,
                               (ino64_t)statGet.st_ino,
                               iFlags,
                               iMode,
                               statGet.st_uid,
                               statGet.st_gid,
                               statGet.st_size,
                               (PVOID)plfsn,
                               &bIsNew);
    
    if (pfdnode == LW_NULL) {                                           /*  无法创建 fd_node 节点       */
        __LFS_VOL_UNLOCK(pfs);
        return  (PX_ERROR);
    }
    pfdnode->FDNODE_pvFsExtern = (PVOID)pfs;                            /*  记录文件系统信息            */

    LW_DEV_INC_USE_COUNT(&pfs->LFS_devhdrHdr);                          /*  更新计数器                  */

    __LFS_VOL_UNLOCK(pfs);
    printf("__littleFsOpen end!\n");
    return  ((LONG)pfdnode);                                            /*  返回文件节点                */
}

/*********************************************************************************************************
** 函数名称: __littleFsRemove
** 功能描述: fs remove 操作
** 输　入  : pfs           卷设备
**           pcName           文件名
**           注意文件名如果为空就是卸载本文件系统
** 输　出  : < 0 表示错误
** 全局变量:
** 调用模块:
*********************************************************************************************************/
static INT  __littleFsRemove (PLFS_VOLUME   pfs,
                           PCHAR         pcName)
{
    PLFS_NODE           plfsn;

    plfsn = (PLFS_NODE)__SHEAP_ALLOC(sizeof(LFS_NODE));
    lib_bzero(plfsn, sizeof(LFS_NODE));

    if (pcName == LW_NULL) {
        _ErrorHandle(ERROR_IO_NO_DEVICE_NAME_IN_PATH);
        return  (PX_ERROR);
    }

    if (__LFS_VOL_LOCK(pfs) != ERROR_NONE) {
        _ErrorHandle(ENXIO);                                            /*  设备出错                    */
        return  (PX_ERROR);
    }

    //************************************ TODO ************************************
    struct lfs_info lfsinfo;
    int error=lfs_stat(&pfs->lfst,pcName,&lfsinfo);
    int openerror=0;
    if(!error){
        if(lfsinfo.type==LFS_TYPE_DIR){
            openerror=lfs_dir_open(&pfs->lfst,&plfsn->lfsdir,pcName);
            plfsn->isfile=false;
        }
        else{
            openerror=lfs_file_open(&pfs->lfst,&plfsn->lfsfile,pcName,LFS_O_RDWR);
            plfsn->isfile=true;
        }
    }else{
        __LFS_VOL_UNLOCK(pfs);
        _ErrorHandle(ENOENT);
        return  (PX_ERROR);
    }

    if (openerror>=0) {
        lfs_remove(&pfs->lfst,pcName);
        __LFS_VOL_UNLOCK(pfs);
        return  (ERROR_NONE);

    } else if (!pcName) {                                               /*    删除 lfs 文件系统           */
        if (pfs->LFS_bValid == LW_FALSE) {
            __LFS_VOL_UNLOCK(pfs);
            return  (ERROR_NONE);                                       /*    正在被其他任务卸载          */
        }

__re_umount_vol:
    if (LW_DEV_GET_USE_COUNT((LW_DEV_HDR *)pfs)) {
        if (!pfs->LFS_bForceDelete) {
            __LFS_VOL_UNLOCK(pfs);
            _ErrorHandle(EBUSY);
            return  (PX_ERROR);
        }

        pfs->LFS_bValid = LW_FALSE;

        __LFS_VOL_UNLOCK(pfs);

        _DebugHandle(__ERRORMESSAGE_LEVEL, "LittleFS: disk have open file.\r\n");
        iosDevFileAbnormal(&pfs->LFS_devhdrHdr);                          /*  将所有相关文件设为异常模式  */

        __LFS_VOL_LOCK(pfs);
        goto __re_umount_vol;

    } else {
        pfs->LFS_bValid = LW_FALSE;
    }

        iosDevDelete((LW_DEV_HDR *)pfs);                                  /*      IO 系统移除设备             */
        API_SemaphoreMDelete(&pfs->LFS_hVolLock);

        lfs_unmount(&pfs->lfst);                                          /*      释放所有文件内容            */
        __SHEAP_FREE(pfs);

        _DebugHandle(__LOGMESSAGE_LEVEL, "LittleFS: Lfs unmount ok.\r\n");

        return  (ERROR_NONE);

    } else {
        __LFS_VOL_UNLOCK(pfs);
        _ErrorHandle(ENOENT);
        return  (PX_ERROR);
    }
}

/*********************************************************************************************************
** 函数名称: __littleFsClose
** 功能描述: fs close 操作
** 输　入  : pfdentry         文件控制块
** 输　出  : < 0 表示错误
** 全局变量:
** 调用模块:
*********************************************************************************************************/
static INT  __littleFsClose (PLW_FD_ENTRY    pfdentry)
{
    PLW_FD_NODE   pfdnode = (PLW_FD_NODE)pfdentry->FDENTRY_pfdnode;
    PLFS_NODE     plfsn   = (PLFS_NODE)pfdnode->FDNODE_pvFile;
    PLFS_VOLUME   pfs  = (PLFS_VOLUME)pfdnode->FDNODE_pvFsExtern;
    BOOL          bRemove = LW_FALSE;

    printf("__littleFsClose begin!\n");

    if (__LFS_VOL_LOCK(pfs) != ERROR_NONE) {                              /*        设备出错            */
        _ErrorHandle(ENXIO);                                           
        return  (PX_ERROR);
    }

    if (API_IosFdNodeDec(&pfs->LFS_plineFdNodeHeader,
                         pfdnode, &bRemove) == 0) {
        if (plfsn->isfile) {
            lfs_file_close(&pfs->lfst, &plfsn->lfsfile);
        }else{
            lfs_dir_close(&pfs->lfst, &plfsn->lfsdir);
        }
    }

    LW_DEV_DEC_USE_COUNT(&pfs->LFS_devhdrHdr);

    __LFS_VOL_UNLOCK(pfs);
    printf("__littleFsClose end!\n");

    return  (ERROR_NONE);
}

/*********************************************************************************************************
** 函数名称: __littleFsRead
** 功能描述: fs read 操作
** 输　入  : pfdentry         文件控制块
**           pcBuffer         接收缓冲区
**           stMaxBytes       接收缓冲区大小
** 输　出  : 驱动相关
** 全局变量:
** 调用模块:
*********************************************************************************************************/
static ssize_t  __littleFsRead (PLW_FD_ENTRY pfdentry,
                             PCHAR        pcBuffer,
                             size_t       stMaxBytes)
{
    PLW_FD_NODE   pfdnode    = (PLW_FD_NODE)pfdentry->FDENTRY_pfdnode;
    PLFS_NODE     plfsn      = (PLFS_NODE)pfdnode->FDNODE_pvFile;
    ssize_t       sstReadNum = PX_ERROR;

    if (!pcBuffer) {
        _ErrorHandle(EINVAL);
        return  (PX_ERROR);
    }

    if (plfsn == LW_NULL) {
        _ErrorHandle(EISDIR);
        return  (PX_ERROR);
    }

    if (__LFS_FILE_LOCK(plfsn) != ERROR_NONE) {
        _ErrorHandle(ENXIO);
        return  (PX_ERROR);
    }

    if (S_ISDIR(plfsn->LFSN_mode)) {
        __LFS_FILE_UNLOCK(plfsn);
        _ErrorHandle(EISDIR);
        return  (PX_ERROR);
    }

    if (stMaxBytes) {
        if(!plfsn->isfile){
            _DebugHandle(__LOGMESSAGE_LEVEL, "LittleFS: you can not resd a directory.\r\n");
        }else{
            sstReadNum = lfs_file_read(&plfsn->LFSN_plfs->lfst, &plfsn->lfsfile, pcBuffer, stMaxBytes);
            if (sstReadNum > 0) {
                pfdentry->FDENTRY_oftPtr += (off_t)sstReadNum;              /*  更新文件指针                */
            }
        }
    } else {
        sstReadNum = 0;
    }

    __LFS_FILE_UNLOCK(plfsn);

    return  (sstReadNum);
}

/*********************************************************************************************************
** 函数名称: __littleFsPRead
** 功能描述: fs pread 操作
** 输　入  : pfdentry         文件控制块
**           pcBuffer         接收缓冲区
**           stMaxBytes       接收缓冲区大小
**           oftPos           位置
** 输　出  : 驱动相关
** 全局变量:
** 调用模块:
*********************************************************************************************************/
static ssize_t  __littleFsPRead (PLW_FD_ENTRY pfdentry,
                              PCHAR        pcBuffer,
                              size_t       stMaxBytes,
                              off_t        oftPos)
{
    PLW_FD_NODE   pfdnode    = (PLW_FD_NODE)pfdentry->FDENTRY_pfdnode;
    PLFS_NODE     plfsn      = (PLFS_NODE)pfdnode->FDNODE_pvFile;
    ssize_t       sstReadNum = PX_ERROR;

    if (!pcBuffer || (oftPos < 0)) {
        _ErrorHandle(EINVAL);
        return  (PX_ERROR);
    }

    if (plfsn == LW_NULL) {
        _ErrorHandle(EISDIR);
        return  (PX_ERROR);
    }

    if (__LFS_FILE_LOCK(plfsn) != ERROR_NONE) {
        _ErrorHandle(ENXIO);
        return  (PX_ERROR);
    }

    if (S_ISDIR(plfsn->LFSN_mode)) {
        __LFS_FILE_UNLOCK(plfsn);
        _ErrorHandle(EISDIR);
        return  (PX_ERROR);
    }

    if (stMaxBytes) {
        if(!plfsn->isfile){
            _DebugHandle(__LOGMESSAGE_LEVEL, "LittleFS: you can not resd a directory.\r\n");
        }else{
            lfs_file_seek(&plfsn->LFSN_plfs->lfst, &plfsn->lfsfile,oftPos,LFS_SEEK_SET);
            sstReadNum = lfs_file_read(&plfsn->LFSN_plfs->lfst, &plfsn->lfsfile, pcBuffer, stMaxBytes);
            if (sstReadNum > 0) {
                pfdentry->FDENTRY_oftPtr += (off_t)sstReadNum;              /*  更新文件指针                */
            }
        }

    } else {
        sstReadNum = 0;
    }

    __LFS_FILE_UNLOCK(plfsn);

    return  (sstReadNum);
}

/*********************************************************************************************************
** 函数名称: __littleFsWrite
** 功能描述: fs write 操作
** 输　入  : pfdentry         文件控制块
**           pcBuffer         缓冲区
**           stNBytes         需要写入的数据
** 输　出  : 驱动相关
** 全局变量:
** 调用模块:
*********************************************************************************************************/
static ssize_t  __littleFsWrite (PLW_FD_ENTRY  pfdentry,
                              PCHAR         pcBuffer,
                              size_t        stNBytes)
{
    PLW_FD_NODE   pfdnode     = (PLW_FD_NODE)pfdentry->FDENTRY_pfdnode;
    PLFS_NODE     plfsn       = (PLFS_NODE)pfdnode->FDNODE_pvFile;
    ssize_t       sstWriteNum = PX_ERROR;

    if (!pcBuffer) {
        _ErrorHandle(EINVAL);
        return  (PX_ERROR);
    }

    if (plfsn == LW_NULL) {
        _ErrorHandle(EISDIR);
        return  (PX_ERROR);
    }

    if (__LFS_FILE_LOCK(plfsn) != ERROR_NONE) {
        _ErrorHandle(ENXIO);
        return  (PX_ERROR);
    }

    if (S_ISDIR(plfsn->LFSN_mode)) {
        __LFS_FILE_UNLOCK(plfsn);
        _ErrorHandle(EISDIR);
        return  (PX_ERROR);
    }

    if (pfdentry->FDENTRY_iFlag & O_APPEND) {                           /*  追加模式                    */
        pfdentry->FDENTRY_oftPtr = pfdnode->FDNODE_oftSize;             /*  移动读写指针到末尾          */
    }

    if (stNBytes) {
        if(!plfsn->isfile){
            _DebugHandle(__LOGMESSAGE_LEVEL, "LittleFS: you can not write a directory.\r\n");
        }else{
            sstWriteNum = lfs_file_write(&plfsn->LFSN_plfs->lfst, &plfsn->lfsfile, pcBuffer, stNBytes);
        }
        if (sstWriteNum > 0) {
                pfdentry->FDENTRY_oftPtr += (off_t)sstWriteNum;             /*  更新文件指针                */
                pfdnode->FDNODE_oftSize   = (off_t)plfsn->LFSN_stSize;
        }
    } else {
        sstWriteNum = 0;
    }

    __LFS_FILE_UNLOCK(plfsn);

    return  (sstWriteNum);
}

/*********************************************************************************************************
** 函数名称: __littleFsPWrite
** 功能描述: fs pwrite 操作
** 输　入  : pfdentry         文件控制块
**           pcBuffer         缓冲区
**           stNBytes         需要写入的数据
**           oftPos           位置
** 输　出  : 驱动相关
** 全局变量:
** 调用模块:
*********************************************************************************************************/
static ssize_t  __littleFsPWrite (PLW_FD_ENTRY  pfdentry,
                               PCHAR         pcBuffer,
                               size_t        stNBytes,
                               off_t         oftPos)
{
    PLW_FD_NODE   pfdnode     = (PLW_FD_NODE)pfdentry->FDENTRY_pfdnode;
    PLFS_NODE     plfsn       = (PLFS_NODE)pfdnode->FDNODE_pvFile;
    ssize_t       sstWriteNum = PX_ERROR;

    if (!pcBuffer || (oftPos < 0)) {
        _ErrorHandle(EINVAL);
        return  (PX_ERROR);
    }

    if (plfsn == LW_NULL) {
        _ErrorHandle(EISDIR);
        return  (PX_ERROR);
    }

    if (__LFS_FILE_LOCK(plfsn) != ERROR_NONE) {
        _ErrorHandle(ENXIO);
        return  (PX_ERROR);
    }

    if (S_ISDIR(plfsn->LFSN_mode)) {
        __LFS_FILE_UNLOCK(plfsn);
        _ErrorHandle(EISDIR);
        return  (PX_ERROR);
    }

    if (stNBytes) {
        if(!plfsn->isfile){
            _DebugHandle(__LOGMESSAGE_LEVEL, "LittleFS: you can not write a directory.\r\n");
        }else{
            lfs_file_seek(&plfsn->LFSN_plfs->lfst, &plfsn->lfsfile,oftPos,LFS_SEEK_SET);
            sstWriteNum = lfs_file_write(&plfsn->LFSN_plfs->lfst, &plfsn->lfsfile, pcBuffer, stNBytes);
        }
        if (sstWriteNum > 0) {
                pfdentry->FDENTRY_oftPtr += (off_t)sstWriteNum;             /*  更新文件指针                */
                pfdnode->FDNODE_oftSize   = (off_t)plfsn->LFSN_stSize;
        }
    } else {
        sstWriteNum = 0;
    }

    __LFS_FILE_UNLOCK(plfsn);

    return  (sstWriteNum);
}

/*********************************************************************************************************
** 函数名称: __littleFsNRead
** 功能描述: lfsFs nread 操作
** 输　入  : pfdentry         文件控制块
**           piNRead          剩余数据量
** 输　出  : 驱动相关
** 全局变量:
** 调用模块:
*********************************************************************************************************/
static INT  __littleFsNRead (PLW_FD_ENTRY  pfdentry, INT  *piNRead)
{
    PLW_FD_NODE   pfdnode = (PLW_FD_NODE)pfdentry->FDENTRY_pfdnode;
    PLFS_NODE     plfsn   = (PLFS_NODE)pfdnode->FDNODE_pvFile;

    if (piNRead == LW_NULL) {
        _ErrorHandle(EINVAL);
        return  (PX_ERROR);
    }

    if (plfsn == LW_NULL) {
        _ErrorHandle(EISDIR);
        return  (PX_ERROR);
    }

    if (__LFS_FILE_LOCK(plfsn) != ERROR_NONE) {
        _ErrorHandle(ENXIO);
        return  (PX_ERROR);
    }

    if (S_ISDIR(plfsn->LFSN_mode)) {
        __LFS_FILE_UNLOCK(plfsn);
        _ErrorHandle(EISDIR);
        return  (PX_ERROR);
    }

    *piNRead = (INT)(plfsn->LFSN_stSize - (size_t)pfdentry->FDENTRY_oftPtr);

    __LFS_FILE_UNLOCK(plfsn);

    return  (ERROR_NONE);
}

/*********************************************************************************************************
** 函数名称: __littleFsNRead64
** 功能描述: lfsFs nread 操作
** 输　入  : pfdentry         文件控制块
**           poftNRead        剩余数据量
** 输　出  : 驱动相关
** 全局变量:
** 调用模块:
*********************************************************************************************************/
static INT  __littleFsNRead64 (PLW_FD_ENTRY  pfdentry, off_t  *poftNRead)
{
    PLW_FD_NODE   pfdnode = (PLW_FD_NODE)pfdentry->FDENTRY_pfdnode;
    PLFS_NODE     plfsn   = (PLFS_NODE)pfdnode->FDNODE_pvFile;

    if (plfsn == LW_NULL) {
        _ErrorHandle(EISDIR);
        return  (PX_ERROR);
    }

    if (__LFS_FILE_LOCK(plfsn) != ERROR_NONE) {
        _ErrorHandle(ENXIO);
        return  (PX_ERROR);
    }

    if (S_ISDIR(plfsn->LFSN_mode)) {
        __LFS_FILE_UNLOCK(plfsn);
        _ErrorHandle(EISDIR);
        return  (PX_ERROR);
    }

    *poftNRead = (off_t)(plfsn->LFSN_stSize - (size_t)pfdentry->FDENTRY_oftPtr);

    __LFS_FILE_UNLOCK(plfsn);

    return  (ERROR_NONE);
}

/*********************************************************************************************************
** 函数名称: __littleFsSeek
** 功能描述: lfsFs seek 操作
** 输　入  : pfdentry         文件控制块
**           oftOffset        偏移量
** 输　出  : 驱动相关
** 全局变量:
** 调用模块:
*********************************************************************************************************/
static INT  __littleFsSeek (PLW_FD_ENTRY  pfdentry,
                         off_t         oftOffset)
{
    PLW_FD_NODE   pfdnode = (PLW_FD_NODE)pfdentry->FDENTRY_pfdnode;
    PLFS_NODE     plfsn   = (PLFS_NODE)pfdnode->FDNODE_pvFile;

    if (plfsn == LW_NULL) {
        _ErrorHandle(EISDIR);
        return  (PX_ERROR);
    }

    if (oftOffset > (size_t)~0) {
        _ErrorHandle(EOVERFLOW);
        return  (PX_ERROR);
    }

    if (__LFS_FILE_LOCK(plfsn) != ERROR_NONE) {
        _ErrorHandle(ENXIO);
        return  (PX_ERROR);
    }

    if (S_ISDIR(plfsn->LFSN_mode)) {
        __LFS_FILE_UNLOCK(plfsn);
        _ErrorHandle(EISDIR);
        return  (PX_ERROR);
    }

    lfs_file_seek(&plfsn->LFSN_plfs->lfst, &plfsn->lfsfile,oftOffset,LFS_SEEK_SET);
    pfdentry->FDENTRY_oftPtr = oftOffset;
    if (plfsn->LFSN_stVSize < (size_t)oftOffset) {
        plfsn->LFSN_stVSize = (size_t)oftOffset;
    }

    __LFS_FILE_UNLOCK(plfsn);

    return  (ERROR_NONE);
}
/*********************************************************************************************************
** 函数名称: __littleFsWhere
** 功能描述: lfsFs 获得文件当前读写指针位置 (使用参数作为返回值, 与 FIOWHERE 的要求稍有不同)
** 输　入  : pfdentry            文件控制块
**           poftPos             读写指针位置
** 输　出  : < 0 表示错误
** 全局变量:
** 调用模块:
*********************************************************************************************************/
static INT  __littleFsWhere (PLW_FD_ENTRY  pfdentry, off_t  *poftPos)
{
    if (poftPos) {
        *poftPos = (off_t)pfdentry->FDENTRY_oftPtr;
        return  (ERROR_NONE);
    }

    return  (PX_ERROR);
}
/*********************************************************************************************************
** 函数名称: __littleFsStatGet
** 功能描述: lfsFs stat 操作
** 输　入  : pfdentry         文件控制块
**           pstat            文件状态
** 输　出  : < 0 表示错误
** 全局变量:
** 调用模块:
*********************************************************************************************************/
static INT  __littleFsStat (PLW_FD_ENTRY  pfdentry, struct stat *pstat)
{
    PLW_FD_NODE   pfdnode = (PLW_FD_NODE)pfdentry->FDENTRY_pfdnode;
    PLFS_NODE     plfsn   = (PLFS_NODE)pfdnode->FDNODE_pvFile;
    PLFS_VOLUME   pfs  = (PLFS_VOLUME)pfdnode->FDNODE_pvFsExtern;

    if (!pstat) {
        _ErrorHandle(EINVAL);
        return  (PX_ERROR);
    }

    if (__LFS_VOL_LOCK(pfs) != ERROR_NONE) {
        _ErrorHandle(ENXIO);
        return  (PX_ERROR);
    }

    __lfs_stat(plfsn, pfs, pstat);

    __LFS_VOL_UNLOCK(pfs);

    return  (ERROR_NONE);
}

/*********************************************************************************************************
** 函数名称: __littleFsStatfs
** 功能描述: lfsFs statfs 操作
** 输　入  : pfdentry         文件控制块
**           pstatfs          文件系统状态
** 输　出  : < 0 表示错误
** 全局变量:
** 调用模块:
*********************************************************************************************************/
static INT  __littleFsStatfs (PLW_FD_ENTRY  pfdentry, struct statfs *pstatfs)
{
    PLW_FD_NODE   pfdnode = (PLW_FD_NODE)pfdentry->FDENTRY_pfdnode;
    PLFS_VOLUME   pfs  = (PLFS_VOLUME)pfdnode->FDNODE_pvFsExtern;

    if (!pstatfs) {
        _ErrorHandle(EINVAL);
        return  (PX_ERROR);
    }

    if (__LFS_VOL_LOCK(pfs) != ERROR_NONE) {
        _ErrorHandle(ENXIO);
        return  (PX_ERROR);
    }

    __lfs_statfs(pfs, pstatfs);

    __LFS_VOL_UNLOCK(pfs);

    return  (ERROR_NONE);
}


/*********************************************************************************************************
** 函数名称: __littleFsTimeset
** 功能描述: fs 设置文件时间
** 输　入  : pfdentry            文件控制块
**           utim                utimbuf 结构
** 输　出  : < 0 表示错误
** 全局变量:
** 调用模块:
*********************************************************************************************************/
static INT  __littleFsTimeset (PLW_FD_ENTRY  pfdentry, struct utimbuf  *utim)
{
    PLW_FD_NODE   pfdnode = (PLW_FD_NODE)pfdentry->FDENTRY_pfdnode;
    PLFS_NODE     plfsn   = (PLFS_NODE)pfdnode->FDNODE_pvFile;
    PLFS_VOLUME   pfs  = (PLFS_VOLUME)pfdnode->FDNODE_pvFsExtern;

    if (!utim) {
        _ErrorHandle(EINVAL);
        return  (PX_ERROR);
    }

    if (__LFS_VOL_LOCK(pfs) != ERROR_NONE) {
        _ErrorHandle(ENXIO);
        return  (PX_ERROR);
    }

    if (plfsn) {
        plfsn->LFSN_timeAccess = utim->actime;
        plfsn->LFSN_timeChange = utim->modtime;

    } else {
        pfs->LFS_time = utim->modtime;
    }

    __LFS_VOL_UNLOCK(pfs);

    return  (ERROR_NONE);
}

/*********************************************************************************************************
** 函数名称: __littleFsIoctl
** 功能描述: lfsFs ioctl 操作
** 输　入  : pfdentry           文件控制块
**           request,           命令
**           arg                命令参数
** 输　出  : < 0 表示错误
** 全局变量:
** 调用模块:
*********************************************************************************************************/
static INT  __littleFsIoctl (PLW_FD_ENTRY  pfdentry,
                          INT           iRequest,
                          LONG          lArg)
{
    PLW_FD_NODE   pfdnode = (PLW_FD_NODE)pfdentry->FDENTRY_pfdnode;
    PLFS_VOLUME   pfs  = (PLFS_VOLUME)pfdnode->FDNODE_pvFsExtern;
    off_t         oftTemp;
    INT           iError;

    switch (iRequest) {

    case FIOCONTIG:
    case FIOTRUNC:
    case FIOLABELSET:
    case FIOATTRIBSET:
        if ((pfdentry->FDENTRY_iFlag & O_ACCMODE) == O_RDONLY) {
            _ErrorHandle(ERROR_IO_WRITE_PROTECTED);
            return  (PX_ERROR);
        }
    }

    switch (iRequest) {

    case FIODISKINIT:                                                   /*  磁盘初始化                  */
        return  (ERROR_NONE);

    case FIOSEEK:                                                       /*  文件重定位                  */
        oftTemp = *(off_t *)lArg;
        return  (__littleFsSeek(pfdentry, oftTemp));

    case FIOWHERE:                                                      /*  获得文件当前读写指针        */
        iError = __littleFsWhere(pfdentry, &oftTemp);
        if (iError == PX_ERROR) {
            return  (PX_ERROR);
        } else {
            *(off_t *)lArg = oftTemp;
            return  (ERROR_NONE);
        }

    case FIONREAD:                                                      /*  获得文件剩余字节数          */
        return  (__littleFsNRead(pfdentry, (INT *)lArg));

    case FIONREAD64:                                                    /*  获得文件剩余字节数          */
        iError = __littleFsNRead64(pfdentry, &oftTemp);
        if (iError == PX_ERROR) {
            return  (PX_ERROR);
        } else {
            *(off_t *)lArg = oftTemp;
            return  (ERROR_NONE);
        }

//    case FIORENAME:                                                     /*  文件重命名                  */
//        return  (__littleFsRename(pfdentry, (PCHAR)lArg));
//
    case FIOLABELGET:                                                   /*  获取卷标                    */
    case FIOLABELSET:                                                   /*  设置卷标                    */
        _ErrorHandle(ENOSYS);
        return  (PX_ERROR);

    case FIOFSTATGET:                                                   /*  获得文件状态                */
        return  (__littleFsStat(pfdentry, (struct stat *)lArg));

    case FIOFSTATFSGET:                                                 /*  获得文件系统状态            */
        return  (__littleFsStatfs(pfdentry, (struct statfs *)lArg));

//    case FIOREADDIR:                                                    /*  获取一个目录信息            */
//        return  (__littleFsReadDir(pfdentry, (DIR *)lArg));

    case FIOTIMESET:                                                    /*  设置文件时间                */
        return  (__littleFsTimeset(pfdentry, (struct utimbuf *)lArg));

//    case FIOTRUNC:                                                      /*  改变文件大小                */
//        oftTemp = *(off_t *)lArg;
//        return  (__littleFsTruncate(pfdentry, oftTemp));

    case FIOSYNC:                                                       /*  将文件缓存回写              */
    case FIOFLUSH:
    case FIODATASYNC:
        return  (ERROR_NONE);

//    case FIOCHMOD:
//        return  (__littleFsChmod(pfdentry, (INT)lArg));                    /*  改变文件访问权限            */

    case FIOSETFL:                                                      /*  设置新的 flag               */
        if ((INT)lArg & O_NONBLOCK) {
            pfdentry->FDENTRY_iFlag |= O_NONBLOCK;
        } else {
            pfdentry->FDENTRY_iFlag &= ~O_NONBLOCK;
        }
        return  (ERROR_NONE);
//
//    case FIOCHOWN:                                                      /*  修改文件所属关系            */
//        return  (__littleFsChown(pfdentry, (LW_IO_USR *)lArg));

    case FIOFSTYPE:                                                     /*  获得文件系统类型            */
        *(PCHAR *)lArg = "littleFS FileSystem";
        return  (ERROR_NONE);

    case FIOGETFORCEDEL:                                                /*  强制卸载设备是否被允许      */
        *(BOOL *)lArg = pfs->LFS_bForceDelete;
        return  (ERROR_NONE);

#if LW_CFG_FS_SELECT_EN > 0
    case FIOSELECT:
        if (((PLW_SEL_WAKEUPNODE)lArg)->SELWUN_seltypType != SELEXCEPT) {
            SEL_WAKE_UP((PLW_SEL_WAKEUPNODE)lArg);                      /*  唤醒节点                    */
        }
        return  (ERROR_NONE);

    case FIOUNSELECT:
        if (((PLW_SEL_WAKEUPNODE)lArg)->SELWUN_seltypType != SELEXCEPT) {
            LW_SELWUN_SET_READY((PLW_SEL_WAKEUPNODE)lArg);
        }
        return  (ERROR_NONE);
#endif                                                                  /*  LW_CFG_FS_SELECT_EN > 0     */

    default:
        _ErrorHandle(ENOSYS);
        return  (PX_ERROR);
    }
}


/*********************************************************************************************************
                                           API 函数
** 函数名称: API_LittleFsDrvInstall
** 功能描述: 安装 lfs 文件系统驱动程序
** 输　入  :
** 输　出  : < 0 表示失败
** 全局变量:
** 调用模块:
*********************************************************************************************************/

LW_API INT  API_LittleFsDrvInstall(void)
{
    struct file_operations     fileop;

    if (_G_iLittleFsDrvNum > 0) {
        return  (ERROR_NONE);
    }

    lib_bzero(&fileop, sizeof(struct file_operations));

    fileop.owner = THIS_MODULE;
    fileop.fo_create = __littleFsOpen;
    fileop.fo_release = __littleFsRemove;
    fileop.fo_open = __littleFsOpen;
    fileop.fo_close = __littleFsClose;
    fileop.fo_read = __littleFsRead;
    fileop.fo_read_ex = __littleFsPRead;
    fileop.fo_write = __littleFsWrite;
    fileop.fo_write_ex = __littleFsPWrite;
    fileop.fo_lstat = __littleFsStat;
    fileop.fo_ioctl = __littleFsIoctl;
    // fileop.fo_symlink = __lfsFsSymlink;
    // fileop.fo_readlink = __lfsFsReadlink;

    _G_iLittleFsDrvNum = iosDrvInstallEx2(&fileop, LW_DRV_TYPE_NEW_1);     /*  使用 NEW_1 型设备驱动程序   */

    DRIVER_LICENSE(_G_iLittleFsDrvNum, "GPL->Ver 2.0");
    DRIVER_AUTHOR (_G_iLittleFsDrvNum, "Junwen Zhang");
    DRIVER_DESCRIPTION(_G_iLittleFsDrvNum, "LittleFs driver.");

    _DebugHandle(__LOGMESSAGE_LEVEL, "LittleFs installed.\r\n");

    __fsRegister("lfs", API_LittleFsDevCreate, LW_NULL, LW_NULL);        /*  注册文件系统                */

    return  ((_G_iLittleFsDrvNum > 0) ? (ERROR_NONE) : (PX_ERROR));
}

/*********************************************************************************************************
** 函数名称: API_LittleFsDevCreate
** 功能描述: 创建 lfs 文件系统设备.
** 输　入  : pcName            设备名(设备挂接的节点地址)
** 输　出  : < 0 表示失败
** 全局变量:
** 调用模块:
                                           API 函数
*********************************************************************************************************/
#define NAMESPACE   littleFs
LW_API INT  API_LittleFsDevCreate(PCHAR   pcName, PLW_BLK_DEV  pblkd)
{
    PLFS_VOLUME pfs;
    if (_G_iLittleFsDrvNum <= 0) {
        _DebugHandle(__ERRORMESSAGE_LEVEL, "LittleFS: Driver invalidate.\r\n");
        _ErrorHandle(ERROR_IO_NO_DRIVER);
        return  (PX_ERROR);
    }
    if ((pblkd == LW_NULL) || (pblkd->BLKD_pcName == LW_NULL)) {
        _DebugHandle(__ERRORMESSAGE_LEVEL, "LittleFS: block device invalidate.\r\n");
        _ErrorHandle(ERROR_IOS_DEVICE_NOT_FOUND);
        return  (PX_ERROR);
    }
    if ((pcName == LW_NULL) || __STR_IS_ROOT(pcName)) {
        _DebugHandle(__ERRORMESSAGE_LEVEL, "LittleFS: mount name invalidate.\r\n");
        _ErrorHandle(EFAULT);                                           /*  Bad address             */
        return  (PX_ERROR);
    }

    pfs = (PLFS_VOLUME)__SHEAP_ALLOC(sizeof(LFS_VOLUME));
    if (pfs == LW_NULL) {
        _DebugHandle(__ERRORMESSAGE_LEVEL, "LittleFS: system low memory.\r\n");
        _ErrorHandle(ERROR_SYSTEM_LOW_MEMORY);
        return  (PX_ERROR);
    }
    lib_bzero(pfs, sizeof(LFS_VOLUME));                              /*  清空卷控制块                */

    pfs->LFS_bValid = LW_TRUE;

    pfs->LFS_hVolLock = API_SemaphoreMCreate("LittleFS: lfs_volume_lock", LW_PRIO_DEF_CEILING,
        LW_OPTION_WAIT_PRIORITY | LW_OPTION_DELETE_SAFE |
        LW_OPTION_INHERIT_PRIORITY | LW_OPTION_OBJECT_GLOBAL,
        LW_NULL);

    if (!pfs->LFS_hVolLock) {                                       /*  无法创建卷锁                */
        _DebugHandle(__ERRORMESSAGE_LEVEL, "can't create the lock.\r\n");
        __SHEAP_FREE(pfs);
        return  (PX_ERROR);
    }

    pfs->LFS_mode            = S_IFDIR | DEFAULT_DIR_PERM;
    pfs->LFS_uid             = getuid();
    pfs->LFS_gid             = getgid();
    pfs->LFS_time            = lib_time(LW_NULL);

    int mounterr = lfs_mount(&pfs->lfst, &cfg);
    if(mounterr < 0){
        printf("first lfs inner mount failed!\n");
        int formaterr = lfs_format(&pfs->lfst, &cfg);
        if(formaterr<0) printf("first lfs inner formaterr failed!\n");
        mounterr = lfs_mount(&pfs->lfst, &cfg);
        if(mounterr<0) printf("second lfs inner mount failed!\n");
    }

    if (iosDevAddEx(&pfs->LFS_devhdrHdr, pcName, _G_iLittleFsDrvNum, DT_DIR)
        != ERROR_NONE) {                                                /*  安装文件系统设备            */
        API_SemaphoreMDelete(&pfs->LFS_hVolLock);
        __SHEAP_FREE(pfs);
        return  (PX_ERROR);
    }

    _DebugFormat(__LOGMESSAGE_LEVEL, "LittleFS: target \"%s\" mount ok.\r\n", pcName);
    return  (ERROR_NONE);
}

/*********************************************************************************************************
** 函数名称: API_LittleFsDevDelete
** 功能描述: 删除一个 lfs 文件系统设备, 例如: API_LittleFsDevDelete("/mnt/lfs0");
** 输　入  : pcName            文件系统设备名(物理设备挂接的节点地址)
** 输　出  : < 0 表示失败
** 全局变量:
** 调用模块:
                                           API 函数
*********************************************************************************************************/
LW_API INT  API_LittleFsDevDelete(PCHAR   pcName)
{
    if (API_IosDevMatchFull(pcName)) {                                  /*  如果是设备, 这里就卸载设备  */
        return  (unlink(pcName));

    }
    else {
        _ErrorHandle(ENOENT);
        return  (PX_ERROR);
    }
}

#endif
