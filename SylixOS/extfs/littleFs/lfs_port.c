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
#include "lfs_port.h"

#ifndef LITTLEFS_DISABLE

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
    fileop.fo_lstat = __littleFsLStat;
    fileop.fo_ioctl = __littleFsIoctl;
    fileop.fo_symlink = __littleFsSymlink;
    fileop.fo_readlink = __littleFsReadlink;

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
        // printf("first lfs inner mount failed!\r\n");
        lfs_format(&pfs->lfst, &cfg);
        // if(formaterr<0) printf("first lfs inner formaterr failed!\r\n");
        mounterr = lfs_mount(&pfs->lfst, &cfg);
        // if(mounterr<0) printf("second lfs inner mount failed!\r\n");
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

/*********************************************************************************************************
** 函数名称: __littleOpen
** 功能描述: 打开或者创建文件
** 输　入  :  pfs              内存中littleFs文件系统的super block
**           pcName           文件名
**           iFlags           打开标志，例如读写权限，是否创建
**           iMode            mode_t，文件的类型
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
    BOOL                broot;
    BOOL                bIsNew;

    printf("__littleFsOpen() begin: iFlags: %08x; iMode: %08x \r\n", iFlags, iMode);

    if (pcName == LW_NULL) {                                             /*        无文件名              */
        _ErrorHandle(ERROR_IO_NO_DEVICE_NAME_IN_PATH);
        return  (PX_ERROR);
    }

    if (iFlags & O_CREAT) {                                             /*         创建操作             */
        if (__fsCheckFileName(pcName)) {
            _ErrorHandle(ENOENT);
            return  (PX_ERROR);
        }
        if (S_ISFIFO(iMode) || 
            S_ISBLK(iMode)  ||
            S_ISCHR(iMode)) {
            _ErrorHandle(ERROR_IO_DISK_NOT_PRESENT);                    /*      不支持以上这些格式      */
            return  (PX_ERROR);
        }
    }

    if (__LFS_VOL_LOCK(pfs) != ERROR_NONE) {                             /*         设备加锁            */
        _ErrorHandle(ENXIO);                                             
        return  (PX_ERROR);
    }


    /************************************ TODO ************************************/

    plfsn = __lfs_open(pfs, pcName, iFlags, iMode, &broot);             /*    以非创建的形式打开文件     */
    printf("plfsn:%d\n",(int)plfsn);

    if (!plfsn){
        if (iFlags & O_CREAT){                                          /*      文件不存在，则创建       */
            if (__fsCheckFileName(pcName)) {
                 printf("open with make, __fsCheckFileName() failed!\r\n");
                _ErrorHandle(ENOENT);
                return  (PX_ERROR);
            }
            plfsn = __lfs_maken(pfs, pcName, iMode, NULL);            /*     创建文件或目录节点       */
            if ( plfsn == NULL ) {
                 printf("in __LittleFsOpen(), _fs_maken failed!\r\n");
                return  (PX_ERROR);
            } else{
                 printf("in __LittleFsOpen(), _fs_maken success!\r\n");
                 goto    __file_open_ok;
            }
        }else{
            __LFS_VOL_UNLOCK(pfs);
             printf("__littleFsOpen() end without a node add ############################\r\n\r\n");
            return  (PX_ERROR);
        }
    } else {
        if (!S_ISLNK(plfsn->LFSN_mode)) {
            if ((iFlags & O_CREAT) && (iFlags & O_EXCL)) {              /*  排他创建文件                */
                __LFS_VOL_UNLOCK(pfs);
                _ErrorHandle(EEXIST);                                   /*  已经存在文件                */
                return  (PX_ERROR);
            
            } else if ((iFlags & O_DIRECTORY) && !S_ISDIR(plfsn->LFSN_mode)) {
                __LFS_VOL_UNLOCK(pfs);
                _ErrorHandle(ENOTDIR);
                return  (PX_ERROR);
            
            } else {
                goto    __file_open_ok;
            }
        } 
    }


__file_open_ok:
    __lfs_stat(plfsn, pfs, &statGet);
    pfdnode = API_IosFdNodeAdd(&pfs->LFS_plineFdNodeHeader,            /*        添加文件节点          */
                               statGet.st_dev,
                               (ino64_t)statGet.st_ino,
                               iFlags,
                               plfsn->LFSN_mode,
                               statGet.st_uid,
                               statGet.st_gid,
                               statGet.st_size,
                               (PVOID)plfsn,
                               &bIsNew);
    
    if (pfdnode == LW_NULL) {                                           /*     无法创建 fd_node 节点    */
        __LFS_VOL_UNLOCK(pfs);
        __lfs_unlink(plfsn);                                            /*       删除新建的节点         */
        return  (PX_ERROR);
    }
    pfdnode->FDNODE_pvFsExtern = (PVOID)pfs;                            /*      记录文件系统信息        */

    if ((iFlags & O_TRUNC) && ((iFlags & O_ACCMODE) != O_RDONLY)) {     /*         需要截断             */
        if ( plfsn ) {
            // __lfs_truncate(plfsn, 0); //TODO
            pfdnode->FDNODE_oftSize = 0;
        }
    }

    LW_DEV_INC_USE_COUNT(&pfs->LFS_devhdrHdr);                          /*        更新计数器            */

    __LFS_VOL_UNLOCK(pfs);
    printf("__littleFsOpen end and add node ############################\r\n\r\n");
    return  (pfdnode);                                                  /*        返回文件节点          */
}

/*********************************************************************************************************
** 函数名称: __littleFsRemove
** 功能描述: fs remove 操作
** 输　入  :  pfs           卷设备
**           pcName         文件名
**           注意文件名如果为空就是卸载本文件系统
** 输　出  : < 0 表示错误
** 全局变量:
** 调用模块:
*********************************************************************************************************/
static INT  __littleFsRemove (PLFS_VOLUME   pfs,
                           PCHAR         pcName)
{
    if (pcName == LW_NULL) {
        _ErrorHandle(ERROR_IO_NO_DEVICE_NAME_IN_PATH);
        return  (PX_ERROR);
    }

    if (__LFS_VOL_LOCK(pfs) != ERROR_NONE) {
        _ErrorHandle(ENXIO);                                            /*  设备出错                    */
        return  (PX_ERROR);
    }

    /* 首先判断是否是文件系统根目录 */
    bool broot = FALSE;
    if (*pcName == PX_ROOT) {                                           /*  忽略根符号                  */
        if (pcName[1] == PX_EOS) broot= TRUE;
        else broot = FALSE;
    } else {
        if (pcName[0] == PX_EOS) broot= TRUE;
        else broot = FALSE;


    int err;
    if (broot == FALSE){
        err = lfs_remove(&pfs->lfst, pcName);                           /*        删除 lfs 文件         */
        __LFS_VOL_UNLOCK(pfs);
        return  (err);
    } else {                                                            /*       删除 lfs 文件系统       */
        if (pfs->LFS_bValid == LW_FALSE) {
            __LFS_VOL_UNLOCK(pfs);
            return  (ERROR_NONE);                                       /*      正在被其他任务卸载        */
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
        } 
    }
}

/*********************************************************************************************************
** 函数名称: __littleFsClose
** 功能描述: fs close 操作
** 输　入  : pfdentry         文件控制块
** 输　出  : < 0              表示错误
** 全局变量:
** 调用模块:
*********************************************************************************************************/
static INT  __littleFsClose (PLW_FD_ENTRY    pfdentry)
{
    PLW_FD_NODE   pfdnode = (PLW_FD_NODE)pfdentry->FDENTRY_pfdnode ;
    PLFS_NODE     plfsn   = (PLFS_NODE)  pfdnode->FDNODE_pvFile    ;
    PLFS_VOLUME   pfs     = (PLFS_VOLUME)pfdnode->FDNODE_pvFsExtern;
    BOOL          bRemove = TRUE;


    if (__LFS_VOL_LOCK(pfs) != ERROR_NONE) {                              /*        设备出错            */
        _ErrorHandle(ENXIO);                                           
        return  (PX_ERROR);
    }

    if (API_IosFdNodeDec(&pfs->LFS_plineFdNodeHeader,
                         pfdnode, &bRemove) == 0) {
        if (plfsn){
            if (plfsn->isfile){
                lfs_file_close(&pfs->lfst, &plfsn->lfsfile);
            }else{
                lfs_dir_close(&pfs->lfst, &plfsn->lfsdir);
            }
        }
    }

    LW_DEV_DEC_USE_COUNT(&pfs->LFS_devhdrHdr);

    if (bRemove && plfsn) {
        __lfs_unlink(plfsn);
    }

    __LFS_VOL_UNLOCK(pfs);

    printf("__littleFsClose end ################## \r\n\r\n");
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
            _DebugHandle(__LOGMESSAGE_LEVEL, "LittleFS: you can not read a directory.\r\n");
        }else{
            sstReadNum = lfs_file_read(&plfsn->LFSN_plfs->lfst, &plfsn->lfsfile, pcBuffer, stMaxBytes);
            if (sstReadNum > 0) {
                pfdentry->FDENTRY_oftPtr += (off_t)sstReadNum;              /*  更新文件指针                */
                lfs_file_seek(&plfsn->LFSN_plfs->lfst, &plfsn->lfsfile,sstReadNum,LFS_SEEK_CUR);
            }
        }
    } else {
        sstReadNum = 0;
    }

    __LFS_FILE_UNLOCK(plfsn);
    printf("__littleFsRead end ############################\r\n\r\n");
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
        }
    } else {
        sstReadNum = 0;
    }

    __LFS_FILE_UNLOCK(plfsn);
    printf("__littleFsPRead end ###########################\r\n\r\n");
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
                pfdentry->FDENTRY_oftPtr += (off_t)sstWriteNum;        /*  更新文件指针                */
                lfs_file_seek(&plfsn->LFSN_plfs->lfst, &plfsn->lfsfile,sstWriteNum,LFS_SEEK_CUR);
                pfdnode->FDNODE_oftSize   = lfs_file_size(&plfsn->LFSN_plfs->lfst, &plfsn->lfsfile);
        }
    } else {
        sstWriteNum = 0;
    }

    __LFS_FILE_UNLOCK(plfsn);
    printf("__littleFsWrite end ############################\r\n\r\n");
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
                lfs_file_seek(&plfsn->LFSN_plfs->lfst, &plfsn->lfsfile,sstWriteNum,LFS_SEEK_CUR);
                pfdnode->FDNODE_oftSize   = lfs_file_size(&plfsn->LFSN_plfs->lfst, &plfsn->lfsfile);
        }
    } else {
        sstWriteNum = 0;
    }

    __LFS_FILE_UNLOCK(plfsn);
    printf("__littleFsPWrite end ############################\r\n\r\n");
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
    printf("__littleFsNRead end ############################\r\n\r\n");
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
    printf("__littleFsNRead64 end ############################\r\n\r\n");
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
    printf("__littleFsSeek end ############################\r\n\r\n");
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
** 函数名称: __littleFsStat
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
    printf("__littleFsWhere end ############################\r\n\r\n");
    return  (ERROR_NONE);
}

/*********************************************************************************************************
** 函数名称: __littleFsLStat
** 功能描述: littleFs stat 操作, 通过文件名获取文件状态 
** 输　入  : pfs               lfs 文件系统
**           pcName           文件名
**           pstat            文件状态
** 输　出  : < 0 表示错误
** 全局变量:
** 调用模块:
*********************************************************************************************************/
static INT  __littleFsLStat(PLFS_VOLUME  pfs, PCHAR  pcName, struct stat* pstat)
{   
    PLW_FD_NODE         pfdnode;

    if (!pcName || !pstat) {
        _ErrorHandle(EINVAL);
        return  (PX_ERROR);
    }

    if (__LFS_VOL_LOCK(pfs) != ERROR_NONE) {
        _ErrorHandle(ENXIO);
        return  (PX_ERROR);
    }

    pfdnode = __littleFsOpen(pfs, pcName, O_RDONLY, O_RDONLY);
    if (pfdnode) {
        __lfs_stat((PLFS_NODE)pfdnode->FDNODE_pvFile, pfs, pstat);
    } else if (pcName[0] == PX_EOS) {                                /* 文件系统根目录 */
        __lfs_stat(LW_NULL, pfs, pstat);
    } else {
        __LFS_VOL_UNLOCK(pfs);
        _ErrorHandle(ENOENT);
        return  (PX_ERROR);        
    }

    __LFS_VOL_UNLOCK(pfs);
    printf("__littleFsLStat end ############################\r\n\r\n");
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
    PLW_FD_NODE   pfdnode = (PLW_FD_NODE)pfdentry->FDENTRY_pfdnode  ;
    PLFS_VOLUME   pfs     = (PLFS_VOLUME)pfdnode ->FDNODE_pvFsExtern;

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
    printf("__littleFsStatfs end ############################\r\n\r\n");
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
    PLW_FD_NODE   pfdnode = (PLW_FD_NODE)pfdentry->FDENTRY_pfdnode ;
    PLFS_NODE     plfsn   = (PLFS_NODE)  pfdnode->FDNODE_pvFile    ;
    PLFS_VOLUME   pfs     = (PLFS_VOLUME)pfdnode->FDNODE_pvFsExtern;

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
    printf("__littleFsTimeset end ############################\r\n\r\n");
    return  (ERROR_NONE);
}

/*********************************************************************************************************
** 函数名称: __littleFsReadDir
** 功能描述: littleFs 获得指定目录信息
** 输　入  : pfdentry            文件控制块
**           dir                 目录结构
** 输　出  : < 0 表示错误
** 全局变量:
** 调用模块:
*********************************************************************************************************/
static INT  __littleFsReadDir (PLW_FD_ENTRY  pfdentry, DIR  *dir)
{
    PLW_FD_NODE   pfdnode = (PLW_FD_NODE)pfdentry->FDENTRY_pfdnode ;
    PLFS_NODE     plfsn   = (PLFS_NODE)  pfdnode->FDNODE_pvFile    ;
    PLFS_VOLUME   plfs    = (PLFS_VOLUME)pfdnode->FDNODE_pvFsExtern;
    
    if (!dir) {
        _ErrorHandle(EINVAL);
        return  (PX_ERROR);
    }
    
    if (__LFS_VOL_LOCK(plfs) != ERROR_NONE) {
        _ErrorHandle(ENXIO);
        return  (PX_ERROR);
    }

    /**************************************** TODO *******************************************/
    if (plfsn == LW_NULL) {
         printf("ERROR: plfsn is NULL!\r\n");
        __LFS_VOL_UNLOCK(plfs);
        return (PX_ERROR);
    } else {
        if (!S_ISDIR(plfsn->LFSN_mode)) {
            __LFS_VOL_UNLOCK(plfs);
            _ErrorHandle(ENOTDIR);
            return (PX_ERROR);
        }
    }

    struct lfs_info lfsdirinfo;
    int dirreaderr;
    if(!plfsn->isfile){
        dirreaderr = lfs_dir_read(&plfs->lfst, &plfsn->lfsdir, &lfsdirinfo);
        if(dirreaderr>0){
             printf("dir read success in %d! %d\r\n",plfsn->lfsdir.pos,dirreaderr);
        }else if(dirreaderr<0){
             printf("ERROR: dir read fail in %d! type:%08x\r\n",plfsn->lfsdir.pos,lfsdirinfo.type);
            __LFS_VOL_UNLOCK(plfs);
            return (PX_ERROR);
        }else{
            _ErrorHandle(ENOENT);                               /*  没有多余的节点              */
            __LFS_VOL_UNLOCK(plfs);
            return (PX_ERROR);
        }
    }else{
         printf("ERROR: plfsn is a file!\r\n");
        __LFS_VOL_UNLOCK(plfs);
        return (PX_ERROR);
    }

     printf("dir->dir_pos: %ld", dir->dir_pos);
    dir->dir_pos++;
    
    lib_strlcpy(dir->dir_dirent.d_name, 
                lfsdirinfo.name,
                sizeof(dir->dir_dirent.d_name));
                
    dir->dir_dirent.d_type = genSylixMode(lfsdirinfo.type,0);
    dir->dir_dirent.d_shortname[0] = PX_EOS;

    __LFS_VOL_UNLOCK(plfs);
    printf("__littleFsReadDir end!\r\n");
    return  (ERROR_NONE);
}

/*********************************************************************************************************
** 函数名称: __lfsFsRename
** 功能描述: lfs rename 操作
** 输　入  : pfdentry         文件控制块
**           pcNewName        新的名称
** 输　出  : 驱动相关
** 全局变量:
** 调用模块:
*********************************************************************************************************/
static INT  __littleFsRename (PLW_FD_ENTRY  pfdentry, PCHAR  pcNewName)
{
    PLW_FD_NODE   pfdnode = (PLW_FD_NODE)pfdentry->FDENTRY_pfdnode;
    PLFS_NODE     plfsn   = (PLFS_NODE)pfdnode->FDNODE_pvFile;
    PLFS_VOLUME   plfs    = (PLFS_VOLUME)pfdnode->FDNODE_pvFsExtern;
    PLFS_VOLUME   plfsNew;
    CHAR          cNewPath[PATH_MAX + 1];
    CHAR          cOldPath[PATH_MAX + 1];
    INT           iError;
    
    if (plfsn == LW_NULL) {                                             /*  检查是否为设备文件          */
        _ErrorHandle(ERROR_IOS_DRIVER_NOT_SUP);                         /*  不支持设备重命名            */
        return (PX_ERROR);90
    }
    
    if (pcNewName == LW_NULL) {
        _ErrorHandle(EFAULT);                                           /*  Bad address                 */
        return (PX_ERROR);
    }
    
    if (__STR_IS_ROOT(pcNewName)) {
        _ErrorHandle(ENOENT);
        return (PX_ERROR);
    }
    
    if (__LFS_FILE_LOCK(plfsn) != ERROR_NONE) {
        _ErrorHandle(ENXIO);
        return  (PX_ERROR);
    }

    ioFullFileNameGet(pfdentry->FDENTRY_pcName, 
                          (LW_DEV_HDR **)&plfs, 
                          cOldPath);                                    /*  获得旧目录路径              */
    
    if (ioFullFileNameGet(pcNewName, 
                          (LW_DEV_HDR **)&plfsNew, 
                          cNewPath) != ERROR_NONE) {                    /*  获得新目录路径              */
        __LFS_FILE_UNLOCK(plfsn);
        return  (PX_ERROR);
    }
    
    if (plfsNew != plfs) {                                             /*  必须为同一设备节点          */
        __LFS_FILE_UNLOCK(plfsn);
        _ErrorHandle(EXDEV);
        return  (PX_ERROR);
    }
    
    iError = lfs_rename(&plfs->lfst, cOldPath, cNewPath);
    
    __LFS_FILE_UNLOCK(plfsn);
    printf("__littleFsRename end ############################\r\n\r\n");
    return  (iError);
}

/*********************************************************************************************************
** 函数名称: __littleFsSymlink
** 功能描述: lfsFs 创建符号链接文件
** 输　入  : plfs              romfs 文件系统
**           pcName              链接原始文件名
**           pcLinkDst           链接目标文件名
**           stMaxSize           缓冲大小
** 输　出  : < 0 表示错误
** 全局变量:
** 调用模块:
*********************************************************************************************************/
static INT  __littleFsSymlink (PLFS_VOLUME   plfs,
                            PCHAR         pcName,
                            CPCHAR        pcLinkDst)
{
    PLFS_NODE     plfsn;
    BOOL          broot = FALSE;
    
    if (!pcName || !pcLinkDst) {
        _ErrorHandle(EINVAL);
        return  (PX_ERROR);
    }
    
    if (__fsCheckFileName(pcName)) {
        _ErrorHandle(EINVAL);
        return  (PX_ERROR);
    }
    
    if (__LFS_VOL_LOCK(plfs) != ERROR_NONE) {
        _ErrorHandle(ENXIO);
        return  (PX_ERROR);
    }
    
    plfsn = __lfs_open(plfs, pcName, LW_NULL, LW_NULL, &broot);
    if (plfsn || broot) {
        __LFS_VOL_UNLOCK(plfs);
        _ErrorHandle(EEXIST);
        return  (PX_ERROR);
    }
    
    plfsn = __lfs_maken(plfs, pcName, S_IFLNK | DEFAULT_SYMLINK_PERM, pcLinkDst);
    if (plfsn == LW_NULL) {
        __LFS_VOL_UNLOCK(plfs);
        return  (PX_ERROR);
    }

    /* 这里与RAMFS的创建链接文件不同：
       在LFS里链接文件本质是普通REG文件 + 链接地址属性，故需要关闭这个文件 */
    if (plfsn->isfile){
       lfs_file_close(&plfs->lfst, &plfsn->lfsfile);
    }else{
        lfs_dir_close(&plfs->lfst, &plfsn->lfsdir);
    }
    
    __LFS_VOL_UNLOCK(plfs);
    printf("__littleFsSymlink end ############################\r\n\r\n");
    return  (ERROR_NONE);
}

/*********************************************************************************************************
** 函数名称: __lfsFsReadlink
** 功能描述: lfsFs 读取符号链接文件内容
** 输　入  : plfs              romfs 文件系统
**           pcName              链接原始文件名
**           pcLinkDst           链接目标文件名
**           stMaxSize           缓冲大小
** 输　出  : < 0 表示错误
** 全局变量:
** 调用模块:
*********************************************************************************************************/
static ssize_t __littleFsReadlink (PLFS_VOLUME   plfs,
                                PCHAR         pcName,
                                PCHAR         pcLinkDst,
                                size_t        stMaxSize)
{
    PLFS_NODE   plfsn;
    size_t      stLen;
    BOOL        broot;
    
    if (!pcName || !pcLinkDst || !stMaxSize) {
        _ErrorHandle(EINVAL);
        return  (PX_ERROR);
    }
    
    if (__LFS_VOL_LOCK(plfs) != ERROR_NONE) {
        _ErrorHandle(ENXIO);
        return  (PX_ERROR);
    }
    
    CHAR pcLink[256];
    int getattr = lfs_getattr(&plfs->lfst, pcName, LFS_TYPE_SLINK,
                                      (PCHAR)pcLink, 256);
    
    stLen = getattr;
    
    lib_strncpy(pcLinkDst, (PCHAR)pcLink, stMaxSize);
    
    if (stLen > stMaxSize) {
        stLen = stMaxSize;                                              /*  计算有效字节数              */
    }
    
    __LFS_VOL_UNLOCK(plfs);
    printf("__littleFsReadlink end ############################\r\n\r\n");
    return  ((ssize_t)stLen);
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

    case FIODISKINIT:                                                   /*  磁盘初始化                         */
        return  (ERROR_NONE);

    case FIOSEEK:                                                       /*  文件重定位                         */
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

   case FIORENAME:                                                      /*  文件重命名                  */
       return  (__littleFsRename(pfdentry, (PCHAR)lArg));

    case FIOLABELGET:                                                   /*  获取卷标                    */
    case FIOLABELSET:                                                   /*  设置卷标                    */
        _ErrorHandle(ENOSYS);
        return  (PX_ERROR);

    case FIOFSTATGET:                                                   /*  获得文件状态                */
        return  (__littleFsStat(pfdentry, (struct stat *)lArg));

    case FIOFSTATFSGET:                                                 /*  获得文件系统状态            */
        return  (__littleFsStatfs(pfdentry, (struct statfs *)lArg));

   case FIOREADDIR:                                                    /*  获取一个目录信息            */
       return  (__littleFsReadDir(pfdentry, (DIR *)lArg));

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



#endif
