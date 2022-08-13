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
** 描        述: clfs向上接口文件
*********************************************************************************************************/
#define  __SYLIXOS_STDIO
#define  __SYLIXOS_KERNEL //加了这两句可以使用已定义的内核函数和结构
#include "clfs_port.h"

#ifndef LITTLEFS_DISABLE

/*********************************************************************************************************
                                           API 函数
** 函数名称: API_ClFsDrvInstall
** 功能描述: 安装 clfs 文件系统驱动程序
** 输　入  :
** 输　出  : < 0 表示失败
** 全局变量:
** 调用模块:
*********************************************************************************************************/

LW_API INT  API_ClFsDrvInstall(void)
{
    struct file_operations     fileop;

    if (_G_iClFsDrvNum > 0) {
        return  (ERROR_NONE);
    }

    lib_bzero(&fileop, sizeof(struct file_operations));

    fileop.owner = THIS_MODULE;
    fileop.fo_create = __clFsOpen;
    fileop.fo_release = __clFsRemove;
    fileop.fo_open = __clFsOpen;
    fileop.fo_close = __clFsClose;
    fileop.fo_read = __clFsRead;
    fileop.fo_read_ex = __clFsPRead;
    fileop.fo_write = __clFsWrite;
    fileop.fo_write_ex = __clFsPWrite;
    fileop.fo_lstat = __clFsLStat;
    fileop.fo_ioctl = __clFsIoctl;
    fileop.fo_symlink = __clFsSymlink;
    fileop.fo_readlink = __clFsReadlink;

    _G_iClFsDrvNum = iosDrvInstallEx2(&fileop, LW_DRV_TYPE_NEW_1);     /*  使用 NEW_1 型设备驱动程序   */

    DRIVER_LICENSE(_G_iClFsDrvNum, "GPL->Ver 2.0");
    DRIVER_AUTHOR (_G_iClFsDrvNum, "Junwen Zhang");
    DRIVER_DESCRIPTION(_G_iClFsDrvNum, "ClFs driver.");

    _DebugHandle(__LOGMESSAGE_LEVEL, "ClFs installed.\r\n");

    __fsRegister("clfs", API_ClFsDevCreate, LW_NULL, LW_NULL);        /*  注册文件系统                */

    return  ((_G_iClFsDrvNum > 0) ? (ERROR_NONE) : (PX_ERROR));
}

/*********************************************************************************************************
** 函数名称: API_ClFsDevCreate
** 功能描述: 创建 clfs 文件系统设备.
** 输　入  : pcName            设备名(设备挂接的节点地址)
** 输　出  : < 0 表示失败
** 全局变量:
** 调用模块:
                                           API 函数
*********************************************************************************************************/
#define NAMESPACE   clFs
LW_API INT  API_ClFsDevCreate(PCHAR   pcName, PLW_BLK_DEV  pblkd)
{
    PCLFS_VOLUME pfs;
    if (_G_iClFsDrvNum <= 0) {
        _DebugHandle(__ERRORMESSAGE_LEVEL, "ClFS: Driver invalidate.\r\n");
        _ErrorHandle(ERROR_IO_NO_DRIVER);
        return  (PX_ERROR);
    }
    if ((pblkd == LW_NULL) || (pblkd->BLKD_pcName == LW_NULL)) {
        _DebugHandle(__ERRORMESSAGE_LEVEL, "ClFS: block device invalidate.\r\n");
        _ErrorHandle(ERROR_IOS_DEVICE_NOT_FOUND);
        return  (PX_ERROR);
    }
    if ((pcName == LW_NULL) || __STR_IS_ROOT(pcName)) {
        _DebugHandle(__ERRORMESSAGE_LEVEL, "ClFS: mount name invalidate.\r\n");
        _ErrorHandle(EFAULT);                                           /*  Bad address             */
        return  (PX_ERROR);
    }

    pfs = (PCLFS_VOLUME)__SHEAP_ALLOC(sizeof(CLFS_VOLUME));
    if (pfs == LW_NULL) {
        _DebugHandle(__ERRORMESSAGE_LEVEL, "ClFS: system low memory.\r\n");
        _ErrorHandle(ERROR_SYSTEM_LOW_MEMORY);
        return  (PX_ERROR);
    }
    lib_bzero(pfs, sizeof(CLFS_VOLUME));                              /*  清空卷控制块                */

    pfs->CLFS_bValid = LW_TRUE;

    pfs->CLFS_hVolLock = API_SemaphoreMCreate("ClFS: clfs_volume_lock", LW_PRIO_DEF_CEILING,
        LW_OPTION_WAIT_PRIORITY | LW_OPTION_DELETE_SAFE |
        LW_OPTION_INHERIT_PRIORITY | LW_OPTION_OBJECT_GLOBAL,
        LW_NULL);

    if (!pfs->CLFS_hVolLock) {                                       /*  无法创建卷锁                */
        _DebugHandle(__ERRORMESSAGE_LEVEL, "can't create the lock.\r\n");
        __SHEAP_FREE(pfs);
        return  (PX_ERROR);
    }

    pfs->CLFS_mode            = S_IFDIR | DEFAULT_DIR_PERM;
    pfs->CLFS_uid             = getuid();
    pfs->CLFS_gid             = getgid();
    pfs->CLFS_time            = lib_time(LW_NULL);

    int mounterr = clfs_mount(&pfs->clfst, &cfg);
    if(mounterr < 0){
        // printf("first clfs inner mount failed!\r\n");
        clfs_format(&pfs->clfst, &cfg);
        // if(formaterr<0) printf("first clfs inner formaterr failed!\r\n");
        mounterr = clfs_mount(&pfs->clfst, &cfg);
        // if(mounterr<0) printf("second clfs inner mount failed!\r\n");
    }

    if (iosDevAddEx(&pfs->CLFS_devhdrHdr, pcName, _G_iClFsDrvNum, DT_DIR)
        != ERROR_NONE) {                                                /*  安装文件系统设备            */
        API_SemaphoreMDelete(&pfs->CLFS_hVolLock);
        __SHEAP_FREE(pfs);
        return  (PX_ERROR);
    }

    _DebugFormat(__LOGMESSAGE_LEVEL, "ClFS: target \"%s\" mount ok.\r\n", pcName);
    return  (ERROR_NONE);
}

/*********************************************************************************************************
** 函数名称: API_ClFsDevDelete
** 功能描述: 删除一个 clfs 文件系统设备, 例如: API_ClFsDevDelete("/mnt/clfs0");
** 输　入  : pcName            文件系统设备名(物理设备挂接的节点地址)
** 输　出  : < 0 表示失败
** 全局变量:
** 调用模块:
                                           API 函数
*********************************************************************************************************/
LW_API INT  API_ClFsDevDelete(PCHAR   pcName)
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
** 输　入  :  pfs              内存中clFs文件系统的super block
**           pcName           文件名
**           iFlags           打开标志，例如读写权限，是否创建
**           iMode            mode_t，文件的类型
** 输　出  : < 0 错误
** 全局变量:
** 调用模块:
*********************************************************************************************************/
static LONG __clFsOpen(PCLFS_VOLUME     pfs,
    PCHAR           pcName,
    INT             iFlags,
    INT             iMode )
{
    PLW_FD_NODE         pfdnode;
    PCLFS_NODE           pclfsn;
    struct stat         statGet;
    BOOL                broot;
    BOOL                bIsNew;

    // printf("__clFsOpen() begin: iFlags: %08x; iMode: %08x \r\n", iFlags, iMode);

    if (pcName == LW_NULL) {                                             /*        无文件名              */
        _ErrorHandle(ERROR_IO_NO_DEVICE_NAME_IN_PATH);
        return  (PX_ERROR);
    }

    if (iFlags & O_CREAT) {                                              /*         创建操作             */
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

    if (__CLFS_VOL_LOCK(pfs) != ERROR_NONE) {                             /*         设备加锁            */
        _ErrorHandle(ENXIO);                                             
        return  (PX_ERROR);
    }


    /************************************ TODO ************************************/

    pclfsn = __clfs_open(pfs, pcName, iFlags, iMode, &broot);             /*    以非创建的形式打开文件     */
    // printf("pclfsn:%d\n",(int)pclfsn);

    if (!pclfsn){
        if (iFlags & O_CREAT){                                          /*      文件不存在，则创建       */
            if (__fsCheckFileName(pcName)) {
                //  printf("open with make, __fsCheckFileName() failed!\r\n");
                _ErrorHandle(ENOENT);
                return  (PX_ERROR);
            }
            pclfsn = __clfs_maken(pfs, pcName, iMode, NULL);            /*     创建文件或目录节点       */
            if ( pclfsn == NULL ) {
                //  printf("in __ClFsOpen(), _fs_maken failed!\r\n");
                return  (PX_ERROR);
            } else{
                //  printf("in __ClFsOpen(), _fs_maken success!\r\n");
                 goto    __file_open_ok;
            }
        }else{
            __CLFS_VOL_UNLOCK(pfs);
            // printf("__clFsOpen() end without a node add ! \r\n");
            return  (PX_ERROR);
        }
    } else {
        if (!S_ISLNK(pclfsn->CLFSN_mode)) {
            if ((iFlags & O_CREAT) && (iFlags & O_EXCL)) {              /*  排他创建文件                */
                __CLFS_VOL_UNLOCK(pfs);
                _ErrorHandle(EEXIST);                                   /*  已经存在文件                */
                return  (PX_ERROR);
            
            } else if ((iFlags & O_DIRECTORY) && !S_ISDIR(pclfsn->CLFSN_mode)) {
                __CLFS_VOL_UNLOCK(pfs);
                _ErrorHandle(ENOTDIR);
                return  (PX_ERROR);
            
            } else {
                goto    __file_open_ok;
            }
        } else {
//            printPCHAR(pctemp);
            lib_strcpy((PCHAR)pcName, pclfsn->CLFSN_pcLink);
            __CLFS_VOL_UNLOCK(pfs);
            return ((INT)FOLLOW_LINK_FILE);
        }
    }


__file_open_ok:
    __clfs_stat(pclfsn, pfs, &statGet);
    pfdnode = API_IosFdNodeAdd(&pfs->CLFS_plineFdNodeHeader,            /*        添加文件节点          */
                               statGet.st_dev,
                               (ino64_t)statGet.st_ino,
                               iFlags,
                               pclfsn->CLFSN_mode,
                               statGet.st_uid,
                               statGet.st_gid,
                               statGet.st_size,
                               (PVOID)pclfsn,
                               &bIsNew);
    
    if (pfdnode == LW_NULL) {                                           /*     无法创建 fd_node 节点    */
        __CLFS_VOL_UNLOCK(pfs);
        __clfs_unlink(pclfsn);                                            /*       删除新建的节点         */
        return  (PX_ERROR);
    }
    pfdnode->FDNODE_pvFsExtern = (PVOID)pfs;                            /*      记录文件系统信息        */

    if ((iFlags & O_TRUNC) && ((iFlags & O_ACCMODE) != O_RDONLY)) {     /*         需要截断             */
        if ( pclfsn ) {
            // __clfs_truncate(pclfsn, 0); //TODO
            pfdnode->FDNODE_oftSize = 0;
        }
    }

    LW_DEV_INC_USE_COUNT(&pfs->CLFS_devhdrHdr);                          /*        更新计数器            */

    __CLFS_VOL_UNLOCK(pfs);
    // printf("__clFsOpen end and add node ! \r\n");
    return  (pfdnode);                                                  /*        返回文件节点          */
}

/*********************************************************************************************************
** 函数名称: __clFsRemove
** 功能描述: fs remove 操作
** 输　入  :  pfs           卷设备
**           pcName         文件名
**           注意文件名如果为空就是卸载本文件系统
** 输　出  : < 0 表示错误
** 全局变量:
** 调用模块:
*********************************************************************************************************/
static INT  __clFsRemove (PCLFS_VOLUME   pfs,
                           PCHAR         pcName)
{
    if (pcName == LW_NULL) {
        _ErrorHandle(ERROR_IO_NO_DEVICE_NAME_IN_PATH);
        return  (PX_ERROR);
    }

    if (__CLFS_VOL_LOCK(pfs) != ERROR_NONE) {
        _ErrorHandle(ENXIO);                                            /*  设备出错                    */
        return  (PX_ERROR);
    }

    /* 首先判断是否是文件系统根目录 */
    bool broot = FALSE;
    if (*pcName == PX_ROOT) {                                           /*  忽略根符号                  */
        if (pcName[1] == PX_EOS) broot= TRUE;
    } else {
        if (pcName[0] == PX_EOS) broot= TRUE;
    }


    int err;
    if (broot == FALSE){
        err = clfs_remove(&pfs->clfst, pcName);                           /*        删除 clfs 文件         */
        __CLFS_VOL_UNLOCK(pfs);
        if(err == CLFS_ERR_NOTEMPTY) {
            err=ENOTEMPTY;
            _ErrorHandle(err);
        }
        return  (err);
    } else {                                                            /*       删除 clfs 文件系统       */
        if (pfs->CLFS_bValid == LW_FALSE) {
            __CLFS_VOL_UNLOCK(pfs);
            return  (ERROR_NONE);                                       /*      正在被其他任务卸载        */
        }

__re_umount_vol:
    if (LW_DEV_GET_USE_COUNT((LW_DEV_HDR *)pfs)) {
        if (!pfs->CLFS_bForceDelete) {
            __CLFS_VOL_UNLOCK(pfs);
            _ErrorHandle(EBUSY);
            return  (PX_ERROR);
        }

        pfs->CLFS_bValid = LW_FALSE;

        __CLFS_VOL_UNLOCK(pfs);

        _DebugHandle(__ERRORMESSAGE_LEVEL, "ClFS: disk have open file.\r\n");
        iosDevFileAbnormal(&pfs->CLFS_devhdrHdr);                          /*  将所有相关文件设为异常模式  */

        __CLFS_VOL_LOCK(pfs);
        goto __re_umount_vol;

        } else {
            pfs->CLFS_bValid = LW_FALSE;
        }

            iosDevDelete((LW_DEV_HDR *)pfs);                                  /*      IO 系统移除设备             */
            API_SemaphoreMDelete(&pfs->CLFS_hVolLock);

            clfs_unmount(&pfs->clfst);                                          /*      释放所有文件内容            */
            __SHEAP_FREE(pfs);

            _DebugHandle(__LOGMESSAGE_LEVEL, "ClFS: Clfs unmount ok.\r\n");

            return  (ERROR_NONE);
        } 
}

/*********************************************************************************************************
** 函数名称: __clFsClose
** 功能描述: fs close 操作
** 输　入  : pfdentry         文件控制块
** 输　出  : < 0              表示错误
** 全局变量:
** 调用模块:
*********************************************************************************************************/
static INT  __clFsClose (PLW_FD_ENTRY    pfdentry)
{
    PLW_FD_NODE   pfdnode = (PLW_FD_NODE)pfdentry->FDENTRY_pfdnode ;
    PCLFS_NODE     pclfsn   = (PCLFS_NODE)  pfdnode->FDNODE_pvFile    ;
    PCLFS_VOLUME   pfs     = (PCLFS_VOLUME)pfdnode->FDNODE_pvFsExtern;
    BOOL          bRemove = TRUE;


    if (__CLFS_VOL_LOCK(pfs) != ERROR_NONE) {                              /*        设备出错            */
        _ErrorHandle(ENXIO);                                           
        return  (PX_ERROR);
    }

    if (API_IosFdNodeDec(&pfs->CLFS_plineFdNodeHeader,
                         pfdnode, &bRemove) == 0) {
        if (pclfsn){
            if (pclfsn->isfile){
                clfs_file_close(&pfs->clfst, &pclfsn->clfsfile);
            }else{
                clfs_dir_close(&pfs->clfst, &pclfsn->clfsdir);
            }
        }
    }

    LW_DEV_DEC_USE_COUNT(&pfs->CLFS_devhdrHdr);

    if (bRemove && pclfsn) {
        __clfs_unlink(pclfsn);
    }

    __CLFS_VOL_UNLOCK(pfs);

    // printf("__clFsClose end ! \r\n");
    return  (ERROR_NONE);
}

/*********************************************************************************************************
** 函数名称: __clFsRead
** 功能描述: fs read 操作
** 输　入  : pfdentry         文件控制块
**           pcBuffer         接收缓冲区
**           stMaxBytes       接收缓冲区大小
** 输　出  : 驱动相关
** 全局变量:
** 调用模块:
*********************************************************************************************************/
static ssize_t  __clFsRead (PLW_FD_ENTRY pfdentry,
                             PCHAR        pcBuffer,
                             size_t       stMaxBytes)
{
    PLW_FD_NODE   pfdnode    = (PLW_FD_NODE)pfdentry->FDENTRY_pfdnode;
    PCLFS_NODE     pclfsn      = (PCLFS_NODE)pfdnode->FDNODE_pvFile;
    ssize_t       sstReadNum = PX_ERROR;

    if (!pcBuffer) {
        _ErrorHandle(EINVAL);
        return  (PX_ERROR);
    }

    if (pclfsn == LW_NULL) {
        _ErrorHandle(EISDIR);
        return  (PX_ERROR);
    }

    if (__CLFS_FILE_LOCK(pclfsn) != ERROR_NONE) {
        _ErrorHandle(ENXIO);
        return  (PX_ERROR);
    }

    if (S_ISDIR(pclfsn->CLFSN_mode)) {
        __CLFS_FILE_UNLOCK(pclfsn);
        _ErrorHandle(EISDIR);
        return  (PX_ERROR);
    }

    if (stMaxBytes) {
        if(!pclfsn->isfile){
            _DebugHandle(__LOGMESSAGE_LEVEL, "ClFS: you can not read a directory.\r\n");
        }else{
            sstReadNum = clfs_file_read(&pclfsn->CLFSN_pclfs->clfst, &pclfsn->clfsfile, pcBuffer, stMaxBytes);
            if (sstReadNum > 0) {
                pfdentry->FDENTRY_oftPtr += (off_t)sstReadNum;              /*  更新文件指针                */
                clfs_file_seek(&pclfsn->CLFSN_pclfs->clfst, &pclfsn->clfsfile,sstReadNum,CLFS_SEEK_CUR);
            }
        }
    } else {
        sstReadNum = 0;
    }

    __CLFS_FILE_UNLOCK(pclfsn);
    // printf("__clFsRead end ! \r\n");
    return  (sstReadNum);
}

/*********************************************************************************************************
** 函数名称: __clFsPRead
** 功能描述: fs pread 操作
** 输　入  : pfdentry         文件控制块
**           pcBuffer         接收缓冲区
**           stMaxBytes       接收缓冲区大小
**           oftPos           位置
** 输　出  : 驱动相关
** 全局变量:
** 调用模块:
*********************************************************************************************************/
static ssize_t  __clFsPRead (PLW_FD_ENTRY pfdentry,
                              PCHAR        pcBuffer,
                              size_t       stMaxBytes,
                              off_t        oftPos)
{
    PLW_FD_NODE   pfdnode    = (PLW_FD_NODE)pfdentry->FDENTRY_pfdnode;
    PCLFS_NODE     pclfsn      = (PCLFS_NODE)pfdnode->FDNODE_pvFile;
    ssize_t       sstReadNum = PX_ERROR;

    if (!pcBuffer || (oftPos < 0)) {
        _ErrorHandle(EINVAL);
        return  (PX_ERROR);
    }

    if (pclfsn == LW_NULL) {
        _ErrorHandle(EISDIR);
        return  (PX_ERROR);
    }

    if (__CLFS_FILE_LOCK(pclfsn) != ERROR_NONE) {
        _ErrorHandle(ENXIO);
        return  (PX_ERROR);
    }

    if (S_ISDIR(pclfsn->CLFSN_mode)) {
        __CLFS_FILE_UNLOCK(pclfsn);
        _ErrorHandle(EISDIR);
        return  (PX_ERROR);
    }

    if (stMaxBytes) {
        if(!pclfsn->isfile){
            _DebugHandle(__LOGMESSAGE_LEVEL, "ClFS: you can not resd a directory.\r\n");
        }else{
            clfs_file_seek(&pclfsn->CLFSN_pclfs->clfst, &pclfsn->clfsfile,oftPos,CLFS_SEEK_SET);
            sstReadNum = clfs_file_read(&pclfsn->CLFSN_pclfs->clfst, &pclfsn->clfsfile, pcBuffer, stMaxBytes);
        }
    } else {
        sstReadNum = 0;
    }

    __CLFS_FILE_UNLOCK(pclfsn);
    // printf("__clFsPRead end ! \r\n");
    return  (sstReadNum);
}

/*********************************************************************************************************
** 函数名称: __clFsWrite
** 功能描述: fs write 操作
** 输　入  : pfdentry         文件控制块
**           pcBuffer         缓冲区
**           stNBytes         需要写入的数据
** 输　出  : 驱动相关
** 全局变量:
** 调用模块:
*********************************************************************************************************/
static ssize_t  __clFsWrite (PLW_FD_ENTRY  pfdentry,
                              PCHAR         pcBuffer,
                              size_t        stNBytes)
{
    PLW_FD_NODE   pfdnode     = (PLW_FD_NODE)pfdentry->FDENTRY_pfdnode;
    PCLFS_NODE     pclfsn       = (PCLFS_NODE)pfdnode->FDNODE_pvFile;
    ssize_t       sstWriteNum = PX_ERROR;

    if (!pcBuffer) {
        _ErrorHandle(EINVAL);
        return  (PX_ERROR);
    }

    if (pclfsn == LW_NULL) {
        _ErrorHandle(EISDIR);
        return  (PX_ERROR);
    }

    if (__CLFS_FILE_LOCK(pclfsn) != ERROR_NONE) {
        _ErrorHandle(ENXIO);
        return  (PX_ERROR);
    }

    if (S_ISDIR(pclfsn->CLFSN_mode)) {
        __CLFS_FILE_UNLOCK(pclfsn);
        _ErrorHandle(EISDIR);
        return  (PX_ERROR);
    }

    if (pfdentry->FDENTRY_iFlag & O_APPEND) {                           /*  追加模式                    */
        pfdentry->FDENTRY_oftPtr = pfdnode->FDNODE_oftSize;             /*  移动读写指针到末尾          */
    }

    if (stNBytes) {
        if(!pclfsn->isfile){
            _DebugHandle(__LOGMESSAGE_LEVEL, "ClFS: you can not write a directory.\r\n");
        }else{
            sstWriteNum = clfs_file_write(&pclfsn->CLFSN_pclfs->clfst, &pclfsn->clfsfile, pcBuffer, stNBytes);
        }
        if (sstWriteNum > 0) {
                pfdentry->FDENTRY_oftPtr += (off_t)sstWriteNum;        /*  更新文件指针                */
                clfs_file_seek(&pclfsn->CLFSN_pclfs->clfst, &pclfsn->clfsfile,sstWriteNum,CLFS_SEEK_CUR);
                pfdnode->FDNODE_oftSize   = clfs_file_size(&pclfsn->CLFSN_pclfs->clfst, &pclfsn->clfsfile);
        }
    } else {
        sstWriteNum = 0;
    }

    __CLFS_FILE_UNLOCK(pclfsn);
    // printf("__clFsWrite end ! \r\n");
    return  (sstWriteNum);
}

/*********************************************************************************************************
** 函数名称: __clFsPWrite
** 功能描述: fs pwrite 操作
** 输　入  : pfdentry         文件控制块
**           pcBuffer         缓冲区
**           stNBytes         需要写入的数据
**           oftPos           位置
** 输　出  : 驱动相关
** 全局变量:
** 调用模块:
*********************************************************************************************************/
static ssize_t  __clFsPWrite (PLW_FD_ENTRY  pfdentry,
                               PCHAR         pcBuffer,
                               size_t        stNBytes,
                               off_t         oftPos)
{
    PLW_FD_NODE   pfdnode     = (PLW_FD_NODE)pfdentry->FDENTRY_pfdnode;
    PCLFS_NODE     pclfsn       = (PCLFS_NODE)pfdnode->FDNODE_pvFile;
    ssize_t       sstWriteNum = PX_ERROR;

    if (!pcBuffer || (oftPos < 0)) {
        _ErrorHandle(EINVAL);
        return  (PX_ERROR);
    }

    if (pclfsn == LW_NULL) {
        _ErrorHandle(EISDIR);
        return  (PX_ERROR);
    }

    if (__CLFS_FILE_LOCK(pclfsn) != ERROR_NONE) {
        _ErrorHandle(ENXIO);
        return  (PX_ERROR);
    }

    if (S_ISDIR(pclfsn->CLFSN_mode)) {
        __CLFS_FILE_UNLOCK(pclfsn);
        _ErrorHandle(EISDIR);
        return  (PX_ERROR);
    }

    if (stNBytes) {
        if(!pclfsn->isfile){
            _DebugHandle(__LOGMESSAGE_LEVEL, "ClFS: you can not write a directory.\r\n");
        }else{
            clfs_file_seek(&pclfsn->CLFSN_pclfs->clfst, &pclfsn->clfsfile,oftPos,CLFS_SEEK_SET);
            sstWriteNum = clfs_file_write(&pclfsn->CLFSN_pclfs->clfst, &pclfsn->clfsfile, pcBuffer, stNBytes);
        }
        if (sstWriteNum > 0) {
                pfdentry->FDENTRY_oftPtr += (off_t)sstWriteNum;             /*  更新文件指针                */
                clfs_file_seek(&pclfsn->CLFSN_pclfs->clfst, &pclfsn->clfsfile,sstWriteNum,CLFS_SEEK_CUR);
                pfdnode->FDNODE_oftSize   = clfs_file_size(&pclfsn->CLFSN_pclfs->clfst, &pclfsn->clfsfile);
        }
    } else {
        sstWriteNum = 0;
    }

    __CLFS_FILE_UNLOCK(pclfsn);
    // printf("__clFsPWrite end ! \r\n");
    return  (sstWriteNum);
}

/*********************************************************************************************************
** 函数名称: __clFsNRead
** 功能描述: clfsFs nread 操作
** 输　入  : pfdentry         文件控制块
**           piNRead          剩余数据量
** 输　出  : 驱动相关
** 全局变量:
** 调用模块:
*********************************************************************************************************/
static INT  __clFsNRead (PLW_FD_ENTRY  pfdentry, INT  *piNRead)
{
    PLW_FD_NODE   pfdnode = (PLW_FD_NODE)pfdentry->FDENTRY_pfdnode;
    PCLFS_NODE     pclfsn   = (PCLFS_NODE)pfdnode->FDNODE_pvFile;

    if (piNRead == LW_NULL) {
        _ErrorHandle(EINVAL);
        return  (PX_ERROR);
    }

    if (pclfsn == LW_NULL) {
        _ErrorHandle(EISDIR);
        return  (PX_ERROR);
    }

    if (__CLFS_FILE_LOCK(pclfsn) != ERROR_NONE) {
        _ErrorHandle(ENXIO);
        return  (PX_ERROR);
    }

    if (S_ISDIR(pclfsn->CLFSN_mode)) {
        __CLFS_FILE_UNLOCK(pclfsn);
        _ErrorHandle(EISDIR);
        return  (PX_ERROR);
    }

    *piNRead = (INT)(pclfsn->CLFSN_stSize - (size_t)pfdentry->FDENTRY_oftPtr);

    __CLFS_FILE_UNLOCK(pclfsn);
    // printf("__clFsNRead end ! \r\n");
    return  (ERROR_NONE);
}

/*********************************************************************************************************
** 函数名称: __clFsNRead64
** 功能描述: clfsFs nread 操作
** 输　入  : pfdentry         文件控制块
**           poftNRead        剩余数据量
** 输　出  : 驱动相关
** 全局变量:
** 调用模块:
*********************************************************************************************************/
static INT  __clFsNRead64 (PLW_FD_ENTRY  pfdentry, off_t  *poftNRead)
{
    PLW_FD_NODE   pfdnode = (PLW_FD_NODE)pfdentry->FDENTRY_pfdnode;
    PCLFS_NODE     pclfsn   = (PCLFS_NODE)pfdnode->FDNODE_pvFile;

    if (pclfsn == LW_NULL) {
        _ErrorHandle(EISDIR);
        return  (PX_ERROR);
    }

    if (__CLFS_FILE_LOCK(pclfsn) != ERROR_NONE) {
        _ErrorHandle(ENXIO);
        return  (PX_ERROR);
    }

    if (S_ISDIR(pclfsn->CLFSN_mode)) {
        __CLFS_FILE_UNLOCK(pclfsn);
        _ErrorHandle(EISDIR);
        return  (PX_ERROR);
    }

    *poftNRead = (off_t)(pclfsn->CLFSN_stSize - (size_t)pfdentry->FDENTRY_oftPtr);

    __CLFS_FILE_UNLOCK(pclfsn);
    // printf("__clFsNRead64 end ! \r\n");
    return  (ERROR_NONE);
}

/*********************************************************************************************************
** 函数名称: __clFsSeek
** 功能描述: clfsFs seek 操作
** 输　入  : pfdentry         文件控制块
**           oftOffset        偏移量
** 输　出  : 驱动相关
** 全局变量:
** 调用模块:
*********************************************************************************************************/
static INT  __clFsSeek (PLW_FD_ENTRY  pfdentry,
                         off_t         oftOffset)
{
    PLW_FD_NODE   pfdnode = (PLW_FD_NODE)pfdentry->FDENTRY_pfdnode;
    PCLFS_NODE     pclfsn   = (PCLFS_NODE)pfdnode->FDNODE_pvFile;

    if (pclfsn == LW_NULL) {
        _ErrorHandle(EISDIR);
        return  (PX_ERROR);
    }

    if (oftOffset > (size_t)~0) {
        _ErrorHandle(EOVERFLOW);
        return  (PX_ERROR);
    }

    if (__CLFS_FILE_LOCK(pclfsn) != ERROR_NONE) {
        _ErrorHandle(ENXIO);
        return  (PX_ERROR);
    }

    if (S_ISDIR(pclfsn->CLFSN_mode)) {
        __CLFS_FILE_UNLOCK(pclfsn);
        _ErrorHandle(EISDIR);
        return  (PX_ERROR);
    }

    clfs_file_seek(&pclfsn->CLFSN_pclfs->clfst, &pclfsn->clfsfile,oftOffset,CLFS_SEEK_SET);
    pfdentry->FDENTRY_oftPtr = oftOffset;
    if (pclfsn->CLFSN_stVSize < (size_t)oftOffset) {
        pclfsn->CLFSN_stVSize = (size_t)oftOffset;
    }

    __CLFS_FILE_UNLOCK(pclfsn);
    // printf("__clFsSeek end ! \r\n");
    return  (ERROR_NONE);
}
/*********************************************************************************************************
** 函数名称: __clFsWhere
** 功能描述: clfsFs 获得文件当前读写指针位置 (使用参数作为返回值, 与 FIOWHERE 的要求稍有不同)
** 输　入  : pfdentry            文件控制块
**           poftPos             读写指针位置
** 输　出  : < 0 表示错误
** 全局变量:
** 调用模块:
*********************************************************************************************************/
static INT  __clFsWhere (PLW_FD_ENTRY  pfdentry, off_t  *poftPos)
{
    if (poftPos) {
        *poftPos = (off_t)pfdentry->FDENTRY_oftPtr;
        return  (ERROR_NONE);
    }

    return  (PX_ERROR);
}
/*********************************************************************************************************
** 函数名称: __clFsStat
** 功能描述: clfsFs stat 操作
** 输　入  : pfdentry         文件控制块
**           pstat            文件状态
** 输　出  : < 0 表示错误
** 全局变量:
** 调用模块:
*********************************************************************************************************/
static INT  __clFsStat (PLW_FD_ENTRY  pfdentry, struct stat *pstat)
{
    PLW_FD_NODE   pfdnode = (PLW_FD_NODE)pfdentry->FDENTRY_pfdnode;
    PCLFS_NODE     pclfsn   = (PCLFS_NODE)pfdnode->FDNODE_pvFile;
    PCLFS_VOLUME   pfs  = (PCLFS_VOLUME)pfdnode->FDNODE_pvFsExtern;

    if (!pstat) {
        _ErrorHandle(EINVAL);
        return  (PX_ERROR);
    }

    if (__CLFS_VOL_LOCK(pfs) != ERROR_NONE) {
        _ErrorHandle(ENXIO);
        return  (PX_ERROR);
    }

    __clfs_stat(pclfsn, pfs, pstat);

    __CLFS_VOL_UNLOCK(pfs);
    // printf("__clFsWhere end ! \r\n");
    return  (ERROR_NONE);
}

/*********************************************************************************************************
** 函数名称: __clFsLStat
** 功能描述: clFs stat 操作, 通过文件名获取文件状态 
** 输　入  : pfs               clfs 文件系统
**           pcName           文件名
**           pstat            文件状态
** 输　出  : < 0 表示错误
** 全局变量:
** 调用模块:
*********************************************************************************************************/
static INT  __clFsLStat(PCLFS_VOLUME  pfs, PCHAR  pcName, struct stat* pstat)
{   
    PLW_FD_NODE         pclfsn;
    BOOL                broot;

    if (!pcName || !pstat) {
        _ErrorHandle(EINVAL);
        return  (PX_ERROR);
    }

    if (__CLFS_VOL_LOCK(pfs) != ERROR_NONE) {
        _ErrorHandle(ENXIO);
        return  (PX_ERROR);
    }

    pclfsn = __clfs_open(pfs, pcName, O_RDONLY, O_RDONLY, &broot); //TODO
    if (pclfsn) {
        __clfs_stat((PCLFS_NODE)pclfsn, pfs, pstat);
    } else if (pcName[0] == PX_EOS) {                                /* 文件系统根目录 */
        __clfs_stat(LW_NULL, pfs, pstat);
    } else {
        __CLFS_VOL_UNLOCK(pfs);
        _ErrorHandle(ENOENT);
        return  (PX_ERROR);        
    }

    __CLFS_VOL_UNLOCK(pfs);
    // printf("__clFsLStat end ! \r\n");
    return  (ERROR_NONE);
}

/*********************************************************************************************************
** 函数名称: __clFsStatfs
** 功能描述: clfsFs statfs 操作
** 输　入  : pfdentry         文件控制块
**           pstatfs          文件系统状态
** 输　出  : < 0 表示错误
** 全局变量:
** 调用模块:
*********************************************************************************************************/
static INT  __clFsStatfs (PLW_FD_ENTRY  pfdentry, struct statfs *pstatfs)
{
    PLW_FD_NODE   pfdnode = (PLW_FD_NODE)pfdentry->FDENTRY_pfdnode  ;
    PCLFS_VOLUME   pfs     = (PCLFS_VOLUME)pfdnode ->FDNODE_pvFsExtern;

    if (!pstatfs) {
        _ErrorHandle(EINVAL);
        return  (PX_ERROR);
    }

    if (__CLFS_VOL_LOCK(pfs) != ERROR_NONE) {
        _ErrorHandle(ENXIO);
        return  (PX_ERROR);
    }

    __clfs_statfs(pfs, pstatfs);

    __CLFS_VOL_UNLOCK(pfs);
    // printf("__clFsStatfs end ! \r\n");
    return  (ERROR_NONE);
}


/*********************************************************************************************************
** 函数名称: __clFsTimeset
** 功能描述: fs 设置文件时间
** 输　入  : pfdentry            文件控制块
**           utim                utimbuf 结构
** 输　出  : < 0 表示错误
** 全局变量:
** 调用模块:
*********************************************************************************************************/
static INT  __clFsTimeset (PLW_FD_ENTRY  pfdentry, struct utimbuf  *utim)
{
    PLW_FD_NODE   pfdnode = (PLW_FD_NODE)pfdentry->FDENTRY_pfdnode ;
    PCLFS_NODE     pclfsn   = (PCLFS_NODE)  pfdnode->FDNODE_pvFile    ;
    PCLFS_VOLUME   pfs     = (PCLFS_VOLUME)pfdnode->FDNODE_pvFsExtern;

    if (!utim) {
        _ErrorHandle(EINVAL);
        return  (PX_ERROR);
    }

    if (__CLFS_VOL_LOCK(pfs) != ERROR_NONE) {
        _ErrorHandle(ENXIO);
        return  (PX_ERROR);
    }

    if (pclfsn) {
        pclfsn->CLFSN_timeAccess = utim->actime;
        pclfsn->CLFSN_timeChange = utim->modtime;

    } else {
        pfs->CLFS_time = utim->modtime;
    }

    __CLFS_VOL_UNLOCK(pfs);
    // printf("__clFsTimeset end ! \r\n");
    return  (ERROR_NONE);
}

/*********************************************************************************************************
** 函数名称: __clFsReadDir
** 功能描述: clFs 获得指定目录信息
** 输　入  : pfdentry            文件控制块
**           dir                 目录结构
** 输　出  : < 0 表示错误
** 全局变量:
** 调用模块:
*********************************************************************************************************/
static INT  __clFsReadDir (PLW_FD_ENTRY  pfdentry, DIR  *dir)
{
    PLW_FD_NODE   pfdnode = (PLW_FD_NODE)pfdentry->FDENTRY_pfdnode ;
    PCLFS_NODE     pclfsn   = (PCLFS_NODE)  pfdnode->FDNODE_pvFile    ;
    PCLFS_VOLUME   pclfs    = (PCLFS_VOLUME)pfdnode->FDNODE_pvFsExtern;
    
    if (!dir) {
        _ErrorHandle(EINVAL);
        return  (PX_ERROR);
    }
    
    if (__CLFS_VOL_LOCK(pclfs) != ERROR_NONE) {
        _ErrorHandle(ENXIO);
        return  (PX_ERROR);
    }

    /**************************************** TODO *******************************************/
    if (pclfsn == LW_NULL) {
        //  printf("ERROR: pclfsn is NULL!\r\n");
        __CLFS_VOL_UNLOCK(pclfs);
        return (PX_ERROR);
    } else {
        if (!S_ISDIR(pclfsn->CLFSN_mode)) {
            __CLFS_VOL_UNLOCK(pclfs);
            _ErrorHandle(ENOTDIR);
            return (PX_ERROR);
        }
    }

    struct clfs_info clfsdirinfo;
    int dirreaderr;
    if(!pclfsn->isfile){
        dirreaderr = clfs_dir_read(&pclfs->clfst, &pclfsn->clfsdir, &clfsdirinfo);
        if(dirreaderr>0){
            //  printf("dir read success in %d! %d\r\n",pclfsn->clfsdir.pos,dirreaderr);
        }else if(dirreaderr<0){
            //  printf("ERROR: dir read fail in %d! type:%08x\r\n",pclfsn->clfsdir.pos,clfsdirinfo.type);
            __CLFS_VOL_UNLOCK(pclfs);
            return (PX_ERROR);
        }else{
            _ErrorHandle(ENOENT);                               /*  没有多余的节点              */
            __CLFS_VOL_UNLOCK(pclfs);
            return (PX_ERROR);
        }
    }else{
        //  printf("ERROR: pclfsn is a file!\r\n");
        __CLFS_VOL_UNLOCK(pclfs);
        return (PX_ERROR);
    }

    //  printf("dir->dir_pos: %ld", dir->dir_pos);
    dir->dir_pos++;
    
    lib_strlcpy(dir->dir_dirent.d_name, 
                clfsdirinfo.name,
                sizeof(dir->dir_dirent.d_name));
                
    dir->dir_dirent.d_type = genSylixMode(clfsdirinfo.type,0);
    dir->dir_dirent.d_shortname[0] = PX_EOS;

    __CLFS_VOL_UNLOCK(pclfs);
    // printf("__clFsReadDir end!\r\n");
    return  (ERROR_NONE);
}

/*********************************************************************************************************
** 函数名称: __clfsFsRename
** 功能描述: clfs rename 操作
** 输　入  : pfdentry         文件控制块
**           pcNewName        新的名称
** 输　出  : 驱动相关
** 全局变量:
** 调用模块:
*********************************************************************************************************/
static INT  __clFsRename (PLW_FD_ENTRY  pfdentry, PCHAR  pcNewName)
{
    PLW_FD_NODE   pfdnode = (PLW_FD_NODE)pfdentry->FDENTRY_pfdnode;
    PCLFS_NODE     pclfsn   = (PCLFS_NODE)pfdnode->FDNODE_pvFile;
    PCLFS_VOLUME   pclfs    = (PCLFS_VOLUME)pfdnode->FDNODE_pvFsExtern;
    PCLFS_VOLUME   pclfsNew;
    CHAR          cNewPath[PATH_MAX + 1];
    CHAR          cOldPath[PATH_MAX + 1];
    INT           iError;
    
    if (pclfsn == LW_NULL) {                                             /*  检查是否为设备文件          */
        _ErrorHandle(ERROR_IOS_DRIVER_NOT_SUP);                         /*  不支持设备重命名            */
        return (PX_ERROR);    }
    
    if (pcNewName == LW_NULL) {
        _ErrorHandle(EFAULT);                                           /*  Bad address                 */
        return (PX_ERROR);
    }
    
    if (__STR_IS_ROOT(pcNewName)) {
        _ErrorHandle(ENOENT);
        return (PX_ERROR);
    }
    
    if (__CLFS_FILE_LOCK(pclfsn) != ERROR_NONE) {
        _ErrorHandle(ENXIO);
        return  (PX_ERROR);
    }

    ioFullFileNameGet(pfdentry->FDENTRY_pcName, 
                          (LW_DEV_HDR **)&pclfs, 
                          cOldPath);                                    /*  获得旧目录路径              */
    
    if (ioFullFileNameGet(pcNewName, 
                          (LW_DEV_HDR **)&pclfsNew, 
                          cNewPath) != ERROR_NONE) {                    /*  获得新目录路径              */
        __CLFS_FILE_UNLOCK(pclfsn);
        return  (PX_ERROR);
    }
    
    if (pclfsNew != pclfs) {                                             /*  必须为同一设备节点          */
        __CLFS_FILE_UNLOCK(pclfsn);
        _ErrorHandle(EXDEV);
        return  (PX_ERROR);
    }
    
    iError = clfs_rename(&pclfs->clfst, cOldPath, cNewPath);
    
    __CLFS_FILE_UNLOCK(pclfsn);
    // printf("__clFsRename end ! \r\n");
    return  (iError);
}

/*********************************************************************************************************
** 函数名称: __clFsSymlink
** 功能描述: clfsFs 创建符号链接文件
** 输　入  : pclfs              romfs 文件系统
**           pcName              链接原始文件名
**           pcLinkDst           链接目标文件名
**           stMaxSize           缓冲大小
** 输　出  : < 0 表示错误
** 全局变量:
** 调用模块:
*********************************************************************************************************/
static INT  __clFsSymlink (PCLFS_VOLUME   pclfs,
                            PCHAR         pcName,
                            CPCHAR        pcLinkDst)
{
    PCLFS_NODE     pclfsn;
    BOOL          broot = FALSE;
    
    if (!pcName || !pcLinkDst) {
        _ErrorHandle(EINVAL);
        return  (PX_ERROR);
    }
    
    if (__fsCheckFileName(pcName)) {
        _ErrorHandle(EINVAL);
        return  (PX_ERROR);
    }
    
    if (__CLFS_VOL_LOCK(pclfs) != ERROR_NONE) {
        _ErrorHandle(ENXIO);
        return  (PX_ERROR);
    }
    
    pclfsn = __clfs_open(pclfs, pcName, LW_NULL, LW_NULL, &broot);
    if (pclfsn || broot) {
        __CLFS_VOL_UNLOCK(pclfs);
        _ErrorHandle(EEXIST);
        return  (PX_ERROR);
    }
    
    pclfsn = __clfs_maken(pclfs, pcName, S_IFLNK | DEFAULT_SYMLINK_PERM, pcLinkDst);
    if (pclfsn == LW_NULL) {
        __CLFS_VOL_UNLOCK(pclfs);
        return  (PX_ERROR);
    }

    /* 这里与RAMFS的创建链接文件不同：
       在CLFS里链接文件本质是普通REG文件 + 链接地址属性，故需要关闭这个文件 */
    if (pclfsn->isfile){
       clfs_file_close(&pclfs->clfst, &pclfsn->clfsfile);
    }else{
        clfs_dir_close(&pclfs->clfst, &pclfsn->clfsdir);
    }
    
    __CLFS_VOL_UNLOCK(pclfs);
    // printf("__clFsSymlink end ! \r\n");
    return  (ERROR_NONE);
}

/*********************************************************************************************************
** 函数名称: __clfsFsReadlink
** 功能描述: clfsFs 读取符号链接文件内容
** 输　入  : pclfs              romfs 文件系统
**           pcName              链接原始文件名
**           pcLinkDst           链接目标文件名
**           stMaxSize           缓冲大小
** 输　出  : < 0 表示错误
** 全局变量:
** 调用模块:
*********************************************************************************************************/
static ssize_t __clFsReadlink (PCLFS_VOLUME   pclfs,
                                PCHAR         pcName,
                                PCHAR         pcLinkDst,
                                size_t        stMaxSize)
{
    PCLFS_NODE   pclfsn;
    size_t      stLen;
    BOOL        broot;
    
    if (!pcName || !pcLinkDst || !stMaxSize) {
        _ErrorHandle(EINVAL);
        return  (PX_ERROR);
    }
    
    if (__CLFS_VOL_LOCK(pclfs) != ERROR_NONE) {
        _ErrorHandle(ENXIO);
        return  (PX_ERROR);
    }
    
    CHAR pcLink[256];
    int getattr = clfs_getattr(&pclfs->clfst, pcName, CLFS_TYPE_SLINK,
                                      (PCHAR)pcLink, 256);
    
    stLen = getattr;
    
    lib_strncpy(pcLinkDst, (PCHAR)pcLink, stMaxSize);
    
    if (stLen > stMaxSize) {
        stLen = stMaxSize;                                              /*  计算有效字节数              */
    }
    
    __CLFS_VOL_UNLOCK(pclfs);
    // printf("__clFsReadlink end ! \r\n");
    return  ((ssize_t)stLen);
}

/*********************************************************************************************************
** 函数名称: __clFsIoctl
** 功能描述: clfsFs ioctl 操作
** 输　入  : pfdentry           文件控制块
**           request,           命令
**           arg                命令参数
** 输　出  : < 0 表示错误
** 全局变量:
** 调用模块:
*********************************************************************************************************/
static INT  __clFsIoctl (PLW_FD_ENTRY  pfdentry,
                          INT           iRequest,
                          LONG          lArg)
{
    PLW_FD_NODE   pfdnode = (PLW_FD_NODE)pfdentry->FDENTRY_pfdnode;
    PCLFS_VOLUME   pfs  = (PCLFS_VOLUME)pfdnode->FDNODE_pvFsExtern;
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
        return  (__clFsSeek(pfdentry, oftTemp));

    case FIOWHERE:                                                      /*  获得文件当前读写指针        */
        iError = __clFsWhere(pfdentry, &oftTemp);
        if (iError == PX_ERROR) {
            return  (PX_ERROR);
        } else {
            *(off_t *)lArg = oftTemp;
            return  (ERROR_NONE);
        }

    case FIONREAD:                                                      /*  获得文件剩余字节数          */
        return  (__clFsNRead(pfdentry, (INT *)lArg));

    case FIONREAD64:                                                    /*  获得文件剩余字节数          */
        iError = __clFsNRead64(pfdentry, &oftTemp);
        if (iError == PX_ERROR) {
            return  (PX_ERROR);
        } else {
            *(off_t *)lArg = oftTemp;
            return  (ERROR_NONE);
        }

   case FIORENAME:                                                      /*  文件重命名                  */
       return  (__clFsRename(pfdentry, (PCHAR)lArg));

    case FIOLABELGET:                                                   /*  获取卷标                    */
    case FIOLABELSET:                                                   /*  设置卷标                    */
        _ErrorHandle(ENOSYS);
        return  (PX_ERROR);

    case FIOFSTATGET:                                                   /*  获得文件状态                */
        return  (__clFsStat(pfdentry, (struct stat *)lArg));

    case FIOFSTATFSGET:                                                 /*  获得文件系统状态            */
        return  (__clFsStatfs(pfdentry, (struct statfs *)lArg));

   case FIOREADDIR:                                                    /*  获取一个目录信息            */
       return  (__clFsReadDir(pfdentry, (DIR *)lArg));

    case FIOTIMESET:                                                    /*  设置文件时间                */
        return  (__clFsTimeset(pfdentry, (struct utimbuf *)lArg));

//    case FIOTRUNC:                                                      /*  改变文件大小                */
//        oftTemp = *(off_t *)lArg;
//        return  (__clFsTruncate(pfdentry, oftTemp));

    case FIOSYNC:                                                       /*  将文件缓存回写              */
    case FIOFLUSH:
    case FIODATASYNC:
        return  (ERROR_NONE);

//    case FIOCHMOD:
//        return  (__clFsChmod(pfdentry, (INT)lArg));                    /*  改变文件访问权限            */

    case FIOSETFL:                                                      /*  设置新的 flag               */
        if ((INT)lArg & O_NONBLOCK) {
            pfdentry->FDENTRY_iFlag |= O_NONBLOCK;
        } else {
            pfdentry->FDENTRY_iFlag &= ~O_NONBLOCK;
        }
        return  (ERROR_NONE);
//
//    case FIOCHOWN:                                                      /*  修改文件所属关系            */
//        return  (__clFsChown(pfdentry, (LW_IO_USR *)lArg));

    case FIOFSTYPE:                                                     /*  获得文件系统类型            */
        *(PCHAR *)lArg = "clFS FileSystem";
        return  (ERROR_NONE);

    case FIOGETFORCEDEL:                                                /*  强制卸载设备是否被允许      */
        *(BOOL *)lArg = pfs->CLFS_bForceDelete;
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
