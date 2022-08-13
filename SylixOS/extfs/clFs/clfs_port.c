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
** ��   ��   ��: clfs_port.h
**
** ��   ��   ��: �¿���
**
** �ļ���������: 2022 �� 06 �� 04 ��
**
** ��        ��: clfs���Ͻӿ��ļ�
*********************************************************************************************************/
#define  __SYLIXOS_STDIO
#define  __SYLIXOS_KERNEL //�������������ʹ���Ѷ�����ں˺����ͽṹ
#include "clfs_port.h"

#ifndef LITTLEFS_DISABLE

/*********************************************************************************************************
                                           API ����
** ��������: API_ClFsDrvInstall
** ��������: ��װ clfs �ļ�ϵͳ��������
** �䡡��  :
** �䡡��  : < 0 ��ʾʧ��
** ȫ�ֱ���:
** ����ģ��:
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

    _G_iClFsDrvNum = iosDrvInstallEx2(&fileop, LW_DRV_TYPE_NEW_1);     /*  ʹ�� NEW_1 ���豸��������   */

    DRIVER_LICENSE(_G_iClFsDrvNum, "GPL->Ver 2.0");
    DRIVER_AUTHOR (_G_iClFsDrvNum, "Junwen Zhang");
    DRIVER_DESCRIPTION(_G_iClFsDrvNum, "ClFs driver.");

    _DebugHandle(__LOGMESSAGE_LEVEL, "ClFs installed.\r\n");

    __fsRegister("clfs", API_ClFsDevCreate, LW_NULL, LW_NULL);        /*  ע���ļ�ϵͳ                */

    return  ((_G_iClFsDrvNum > 0) ? (ERROR_NONE) : (PX_ERROR));
}

/*********************************************************************************************************
** ��������: API_ClFsDevCreate
** ��������: ���� clfs �ļ�ϵͳ�豸.
** �䡡��  : pcName            �豸��(�豸�ҽӵĽڵ��ַ)
** �䡡��  : < 0 ��ʾʧ��
** ȫ�ֱ���:
** ����ģ��:
                                           API ����
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
    lib_bzero(pfs, sizeof(CLFS_VOLUME));                              /*  ��վ���ƿ�                */

    pfs->CLFS_bValid = LW_TRUE;

    pfs->CLFS_hVolLock = API_SemaphoreMCreate("ClFS: clfs_volume_lock", LW_PRIO_DEF_CEILING,
        LW_OPTION_WAIT_PRIORITY | LW_OPTION_DELETE_SAFE |
        LW_OPTION_INHERIT_PRIORITY | LW_OPTION_OBJECT_GLOBAL,
        LW_NULL);

    if (!pfs->CLFS_hVolLock) {                                       /*  �޷���������                */
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
        != ERROR_NONE) {                                                /*  ��װ�ļ�ϵͳ�豸            */
        API_SemaphoreMDelete(&pfs->CLFS_hVolLock);
        __SHEAP_FREE(pfs);
        return  (PX_ERROR);
    }

    _DebugFormat(__LOGMESSAGE_LEVEL, "ClFS: target \"%s\" mount ok.\r\n", pcName);
    return  (ERROR_NONE);
}

/*********************************************************************************************************
** ��������: API_ClFsDevDelete
** ��������: ɾ��һ�� clfs �ļ�ϵͳ�豸, ����: API_ClFsDevDelete("/mnt/clfs0");
** �䡡��  : pcName            �ļ�ϵͳ�豸��(�����豸�ҽӵĽڵ��ַ)
** �䡡��  : < 0 ��ʾʧ��
** ȫ�ֱ���:
** ����ģ��:
                                           API ����
*********************************************************************************************************/
LW_API INT  API_ClFsDevDelete(PCHAR   pcName)
{
    if (API_IosDevMatchFull(pcName)) {                                  /*  ������豸, �����ж���豸  */
        return  (unlink(pcName));

    }
    else {
        _ErrorHandle(ENOENT);
        return  (PX_ERROR);
    }
}

/*********************************************************************************************************
** ��������: __littleOpen
** ��������: �򿪻��ߴ����ļ�
** �䡡��  :  pfs              �ڴ���clFs�ļ�ϵͳ��super block
**           pcName           �ļ���
**           iFlags           �򿪱�־�������дȨ�ޣ��Ƿ񴴽�
**           iMode            mode_t���ļ�������
** �䡡��  : < 0 ����
** ȫ�ֱ���:
** ����ģ��:
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

    if (pcName == LW_NULL) {                                             /*        ���ļ���              */
        _ErrorHandle(ERROR_IO_NO_DEVICE_NAME_IN_PATH);
        return  (PX_ERROR);
    }

    if (iFlags & O_CREAT) {                                              /*         ��������             */
        if (__fsCheckFileName(pcName)) {
            _ErrorHandle(ENOENT);
            return  (PX_ERROR);
        }
        if (S_ISFIFO(iMode) || 
            S_ISBLK(iMode)  ||
            S_ISCHR(iMode)) {
            _ErrorHandle(ERROR_IO_DISK_NOT_PRESENT);                    /*      ��֧��������Щ��ʽ      */
            return  (PX_ERROR);
        }
    }

    if (__CLFS_VOL_LOCK(pfs) != ERROR_NONE) {                             /*         �豸����            */
        _ErrorHandle(ENXIO);                                             
        return  (PX_ERROR);
    }


    /************************************ TODO ************************************/

    pclfsn = __clfs_open(pfs, pcName, iFlags, iMode, &broot);             /*    �ԷǴ�������ʽ���ļ�     */
    // printf("pclfsn:%d\n",(int)pclfsn);

    if (!pclfsn){
        if (iFlags & O_CREAT){                                          /*      �ļ������ڣ��򴴽�       */
            if (__fsCheckFileName(pcName)) {
                //  printf("open with make, __fsCheckFileName() failed!\r\n");
                _ErrorHandle(ENOENT);
                return  (PX_ERROR);
            }
            pclfsn = __clfs_maken(pfs, pcName, iMode, NULL);            /*     �����ļ���Ŀ¼�ڵ�       */
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
            if ((iFlags & O_CREAT) && (iFlags & O_EXCL)) {              /*  ���������ļ�                */
                __CLFS_VOL_UNLOCK(pfs);
                _ErrorHandle(EEXIST);                                   /*  �Ѿ������ļ�                */
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
    pfdnode = API_IosFdNodeAdd(&pfs->CLFS_plineFdNodeHeader,            /*        ����ļ��ڵ�          */
                               statGet.st_dev,
                               (ino64_t)statGet.st_ino,
                               iFlags,
                               pclfsn->CLFSN_mode,
                               statGet.st_uid,
                               statGet.st_gid,
                               statGet.st_size,
                               (PVOID)pclfsn,
                               &bIsNew);
    
    if (pfdnode == LW_NULL) {                                           /*     �޷����� fd_node �ڵ�    */
        __CLFS_VOL_UNLOCK(pfs);
        __clfs_unlink(pclfsn);                                            /*       ɾ���½��Ľڵ�         */
        return  (PX_ERROR);
    }
    pfdnode->FDNODE_pvFsExtern = (PVOID)pfs;                            /*      ��¼�ļ�ϵͳ��Ϣ        */

    if ((iFlags & O_TRUNC) && ((iFlags & O_ACCMODE) != O_RDONLY)) {     /*         ��Ҫ�ض�             */
        if ( pclfsn ) {
            // __clfs_truncate(pclfsn, 0); //TODO
            pfdnode->FDNODE_oftSize = 0;
        }
    }

    LW_DEV_INC_USE_COUNT(&pfs->CLFS_devhdrHdr);                          /*        ���¼�����            */

    __CLFS_VOL_UNLOCK(pfs);
    // printf("__clFsOpen end and add node ! \r\n");
    return  (pfdnode);                                                  /*        �����ļ��ڵ�          */
}

/*********************************************************************************************************
** ��������: __clFsRemove
** ��������: fs remove ����
** �䡡��  :  pfs           ���豸
**           pcName         �ļ���
**           ע���ļ������Ϊ�վ���ж�ر��ļ�ϵͳ
** �䡡��  : < 0 ��ʾ����
** ȫ�ֱ���:
** ����ģ��:
*********************************************************************************************************/
static INT  __clFsRemove (PCLFS_VOLUME   pfs,
                           PCHAR         pcName)
{
    if (pcName == LW_NULL) {
        _ErrorHandle(ERROR_IO_NO_DEVICE_NAME_IN_PATH);
        return  (PX_ERROR);
    }

    if (__CLFS_VOL_LOCK(pfs) != ERROR_NONE) {
        _ErrorHandle(ENXIO);                                            /*  �豸����                    */
        return  (PX_ERROR);
    }

    /* �����ж��Ƿ����ļ�ϵͳ��Ŀ¼ */
    bool broot = FALSE;
    if (*pcName == PX_ROOT) {                                           /*  ���Ը�����                  */
        if (pcName[1] == PX_EOS) broot= TRUE;
    } else {
        if (pcName[0] == PX_EOS) broot= TRUE;
    }


    int err;
    if (broot == FALSE){
        err = clfs_remove(&pfs->clfst, pcName);                           /*        ɾ�� clfs �ļ�         */
        __CLFS_VOL_UNLOCK(pfs);
        if(err == CLFS_ERR_NOTEMPTY) {
            err=ENOTEMPTY;
            _ErrorHandle(err);
        }
        return  (err);
    } else {                                                            /*       ɾ�� clfs �ļ�ϵͳ       */
        if (pfs->CLFS_bValid == LW_FALSE) {
            __CLFS_VOL_UNLOCK(pfs);
            return  (ERROR_NONE);                                       /*      ���ڱ���������ж��        */
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
        iosDevFileAbnormal(&pfs->CLFS_devhdrHdr);                          /*  ����������ļ���Ϊ�쳣ģʽ  */

        __CLFS_VOL_LOCK(pfs);
        goto __re_umount_vol;

        } else {
            pfs->CLFS_bValid = LW_FALSE;
        }

            iosDevDelete((LW_DEV_HDR *)pfs);                                  /*      IO ϵͳ�Ƴ��豸             */
            API_SemaphoreMDelete(&pfs->CLFS_hVolLock);

            clfs_unmount(&pfs->clfst);                                          /*      �ͷ������ļ�����            */
            __SHEAP_FREE(pfs);

            _DebugHandle(__LOGMESSAGE_LEVEL, "ClFS: Clfs unmount ok.\r\n");

            return  (ERROR_NONE);
        } 
}

/*********************************************************************************************************
** ��������: __clFsClose
** ��������: fs close ����
** �䡡��  : pfdentry         �ļ����ƿ�
** �䡡��  : < 0              ��ʾ����
** ȫ�ֱ���:
** ����ģ��:
*********************************************************************************************************/
static INT  __clFsClose (PLW_FD_ENTRY    pfdentry)
{
    PLW_FD_NODE   pfdnode = (PLW_FD_NODE)pfdentry->FDENTRY_pfdnode ;
    PCLFS_NODE     pclfsn   = (PCLFS_NODE)  pfdnode->FDNODE_pvFile    ;
    PCLFS_VOLUME   pfs     = (PCLFS_VOLUME)pfdnode->FDNODE_pvFsExtern;
    BOOL          bRemove = TRUE;


    if (__CLFS_VOL_LOCK(pfs) != ERROR_NONE) {                              /*        �豸����            */
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
** ��������: __clFsRead
** ��������: fs read ����
** �䡡��  : pfdentry         �ļ����ƿ�
**           pcBuffer         ���ջ�����
**           stMaxBytes       ���ջ�������С
** �䡡��  : �������
** ȫ�ֱ���:
** ����ģ��:
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
                pfdentry->FDENTRY_oftPtr += (off_t)sstReadNum;              /*  �����ļ�ָ��                */
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
** ��������: __clFsPRead
** ��������: fs pread ����
** �䡡��  : pfdentry         �ļ����ƿ�
**           pcBuffer         ���ջ�����
**           stMaxBytes       ���ջ�������С
**           oftPos           λ��
** �䡡��  : �������
** ȫ�ֱ���:
** ����ģ��:
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
** ��������: __clFsWrite
** ��������: fs write ����
** �䡡��  : pfdentry         �ļ����ƿ�
**           pcBuffer         ������
**           stNBytes         ��Ҫд�������
** �䡡��  : �������
** ȫ�ֱ���:
** ����ģ��:
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

    if (pfdentry->FDENTRY_iFlag & O_APPEND) {                           /*  ׷��ģʽ                    */
        pfdentry->FDENTRY_oftPtr = pfdnode->FDNODE_oftSize;             /*  �ƶ���дָ�뵽ĩβ          */
    }

    if (stNBytes) {
        if(!pclfsn->isfile){
            _DebugHandle(__LOGMESSAGE_LEVEL, "ClFS: you can not write a directory.\r\n");
        }else{
            sstWriteNum = clfs_file_write(&pclfsn->CLFSN_pclfs->clfst, &pclfsn->clfsfile, pcBuffer, stNBytes);
        }
        if (sstWriteNum > 0) {
                pfdentry->FDENTRY_oftPtr += (off_t)sstWriteNum;        /*  �����ļ�ָ��                */
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
** ��������: __clFsPWrite
** ��������: fs pwrite ����
** �䡡��  : pfdentry         �ļ����ƿ�
**           pcBuffer         ������
**           stNBytes         ��Ҫд�������
**           oftPos           λ��
** �䡡��  : �������
** ȫ�ֱ���:
** ����ģ��:
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
                pfdentry->FDENTRY_oftPtr += (off_t)sstWriteNum;             /*  �����ļ�ָ��                */
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
** ��������: __clFsNRead
** ��������: clfsFs nread ����
** �䡡��  : pfdentry         �ļ����ƿ�
**           piNRead          ʣ��������
** �䡡��  : �������
** ȫ�ֱ���:
** ����ģ��:
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
** ��������: __clFsNRead64
** ��������: clfsFs nread ����
** �䡡��  : pfdentry         �ļ����ƿ�
**           poftNRead        ʣ��������
** �䡡��  : �������
** ȫ�ֱ���:
** ����ģ��:
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
** ��������: __clFsSeek
** ��������: clfsFs seek ����
** �䡡��  : pfdentry         �ļ����ƿ�
**           oftOffset        ƫ����
** �䡡��  : �������
** ȫ�ֱ���:
** ����ģ��:
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
** ��������: __clFsWhere
** ��������: clfsFs ����ļ���ǰ��дָ��λ�� (ʹ�ò�����Ϊ����ֵ, �� FIOWHERE ��Ҫ�����в�ͬ)
** �䡡��  : pfdentry            �ļ����ƿ�
**           poftPos             ��дָ��λ��
** �䡡��  : < 0 ��ʾ����
** ȫ�ֱ���:
** ����ģ��:
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
** ��������: __clFsStat
** ��������: clfsFs stat ����
** �䡡��  : pfdentry         �ļ����ƿ�
**           pstat            �ļ�״̬
** �䡡��  : < 0 ��ʾ����
** ȫ�ֱ���:
** ����ģ��:
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
** ��������: __clFsLStat
** ��������: clFs stat ����, ͨ���ļ�����ȡ�ļ�״̬ 
** �䡡��  : pfs               clfs �ļ�ϵͳ
**           pcName           �ļ���
**           pstat            �ļ�״̬
** �䡡��  : < 0 ��ʾ����
** ȫ�ֱ���:
** ����ģ��:
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
    } else if (pcName[0] == PX_EOS) {                                /* �ļ�ϵͳ��Ŀ¼ */
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
** ��������: __clFsStatfs
** ��������: clfsFs statfs ����
** �䡡��  : pfdentry         �ļ����ƿ�
**           pstatfs          �ļ�ϵͳ״̬
** �䡡��  : < 0 ��ʾ����
** ȫ�ֱ���:
** ����ģ��:
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
** ��������: __clFsTimeset
** ��������: fs �����ļ�ʱ��
** �䡡��  : pfdentry            �ļ����ƿ�
**           utim                utimbuf �ṹ
** �䡡��  : < 0 ��ʾ����
** ȫ�ֱ���:
** ����ģ��:
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
** ��������: __clFsReadDir
** ��������: clFs ���ָ��Ŀ¼��Ϣ
** �䡡��  : pfdentry            �ļ����ƿ�
**           dir                 Ŀ¼�ṹ
** �䡡��  : < 0 ��ʾ����
** ȫ�ֱ���:
** ����ģ��:
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
            _ErrorHandle(ENOENT);                               /*  û�ж���Ľڵ�              */
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
** ��������: __clfsFsRename
** ��������: clfs rename ����
** �䡡��  : pfdentry         �ļ����ƿ�
**           pcNewName        �µ�����
** �䡡��  : �������
** ȫ�ֱ���:
** ����ģ��:
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
    
    if (pclfsn == LW_NULL) {                                             /*  ����Ƿ�Ϊ�豸�ļ�          */
        _ErrorHandle(ERROR_IOS_DRIVER_NOT_SUP);                         /*  ��֧���豸������            */
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
                          cOldPath);                                    /*  ��þ�Ŀ¼·��              */
    
    if (ioFullFileNameGet(pcNewName, 
                          (LW_DEV_HDR **)&pclfsNew, 
                          cNewPath) != ERROR_NONE) {                    /*  �����Ŀ¼·��              */
        __CLFS_FILE_UNLOCK(pclfsn);
        return  (PX_ERROR);
    }
    
    if (pclfsNew != pclfs) {                                             /*  ����Ϊͬһ�豸�ڵ�          */
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
** ��������: __clFsSymlink
** ��������: clfsFs �������������ļ�
** �䡡��  : pclfs              romfs �ļ�ϵͳ
**           pcName              ����ԭʼ�ļ���
**           pcLinkDst           ����Ŀ���ļ���
**           stMaxSize           �����С
** �䡡��  : < 0 ��ʾ����
** ȫ�ֱ���:
** ����ģ��:
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

    /* ������RAMFS�Ĵ��������ļ���ͬ��
       ��CLFS�������ļ���������ͨREG�ļ� + ���ӵ�ַ���ԣ�����Ҫ�ر�����ļ� */
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
** ��������: __clfsFsReadlink
** ��������: clfsFs ��ȡ���������ļ�����
** �䡡��  : pclfs              romfs �ļ�ϵͳ
**           pcName              ����ԭʼ�ļ���
**           pcLinkDst           ����Ŀ���ļ���
**           stMaxSize           �����С
** �䡡��  : < 0 ��ʾ����
** ȫ�ֱ���:
** ����ģ��:
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
        stLen = stMaxSize;                                              /*  ������Ч�ֽ���              */
    }
    
    __CLFS_VOL_UNLOCK(pclfs);
    // printf("__clFsReadlink end ! \r\n");
    return  ((ssize_t)stLen);
}

/*********************************************************************************************************
** ��������: __clFsIoctl
** ��������: clfsFs ioctl ����
** �䡡��  : pfdentry           �ļ����ƿ�
**           request,           ����
**           arg                �������
** �䡡��  : < 0 ��ʾ����
** ȫ�ֱ���:
** ����ģ��:
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

    case FIODISKINIT:                                                   /*  ���̳�ʼ��                         */
        return  (ERROR_NONE);

    case FIOSEEK:                                                       /*  �ļ��ض�λ                         */
        oftTemp = *(off_t *)lArg;
        return  (__clFsSeek(pfdentry, oftTemp));

    case FIOWHERE:                                                      /*  ����ļ���ǰ��дָ��        */
        iError = __clFsWhere(pfdentry, &oftTemp);
        if (iError == PX_ERROR) {
            return  (PX_ERROR);
        } else {
            *(off_t *)lArg = oftTemp;
            return  (ERROR_NONE);
        }

    case FIONREAD:                                                      /*  ����ļ�ʣ���ֽ���          */
        return  (__clFsNRead(pfdentry, (INT *)lArg));

    case FIONREAD64:                                                    /*  ����ļ�ʣ���ֽ���          */
        iError = __clFsNRead64(pfdentry, &oftTemp);
        if (iError == PX_ERROR) {
            return  (PX_ERROR);
        } else {
            *(off_t *)lArg = oftTemp;
            return  (ERROR_NONE);
        }

   case FIORENAME:                                                      /*  �ļ�������                  */
       return  (__clFsRename(pfdentry, (PCHAR)lArg));

    case FIOLABELGET:                                                   /*  ��ȡ���                    */
    case FIOLABELSET:                                                   /*  ���þ��                    */
        _ErrorHandle(ENOSYS);
        return  (PX_ERROR);

    case FIOFSTATGET:                                                   /*  ����ļ�״̬                */
        return  (__clFsStat(pfdentry, (struct stat *)lArg));

    case FIOFSTATFSGET:                                                 /*  ����ļ�ϵͳ״̬            */
        return  (__clFsStatfs(pfdentry, (struct statfs *)lArg));

   case FIOREADDIR:                                                    /*  ��ȡһ��Ŀ¼��Ϣ            */
       return  (__clFsReadDir(pfdentry, (DIR *)lArg));

    case FIOTIMESET:                                                    /*  �����ļ�ʱ��                */
        return  (__clFsTimeset(pfdentry, (struct utimbuf *)lArg));

//    case FIOTRUNC:                                                      /*  �ı��ļ���С                */
//        oftTemp = *(off_t *)lArg;
//        return  (__clFsTruncate(pfdentry, oftTemp));

    case FIOSYNC:                                                       /*  ���ļ������д              */
    case FIOFLUSH:
    case FIODATASYNC:
        return  (ERROR_NONE);

//    case FIOCHMOD:
//        return  (__clFsChmod(pfdentry, (INT)lArg));                    /*  �ı��ļ�����Ȩ��            */

    case FIOSETFL:                                                      /*  �����µ� flag               */
        if ((INT)lArg & O_NONBLOCK) {
            pfdentry->FDENTRY_iFlag |= O_NONBLOCK;
        } else {
            pfdentry->FDENTRY_iFlag &= ~O_NONBLOCK;
        }
        return  (ERROR_NONE);
//
//    case FIOCHOWN:                                                      /*  �޸��ļ�������ϵ            */
//        return  (__clFsChown(pfdentry, (LW_IO_USR *)lArg));

    case FIOFSTYPE:                                                     /*  ����ļ�ϵͳ����            */
        *(PCHAR *)lArg = "clFS FileSystem";
        return  (ERROR_NONE);

    case FIOGETFORCEDEL:                                                /*  ǿ��ж���豸�Ƿ�����      */
        *(BOOL *)lArg = pfs->CLFS_bForceDelete;
        return  (ERROR_NONE);

#if LW_CFG_FS_SELECT_EN > 0
    case FIOSELECT:
        if (((PLW_SEL_WAKEUPNODE)lArg)->SELWUN_seltypType != SELEXCEPT) {
            SEL_WAKE_UP((PLW_SEL_WAKEUPNODE)lArg);                      /*  ���ѽڵ�                    */
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
