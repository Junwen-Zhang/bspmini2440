/*********************************************************************************************************
**
**                                    �й�������Դ��֯
**
**                                   Ƕ��ʽʵʱ����ϵͳ
**
**                                     SylixOS(TM)
**
**                               Copyright All Rights Reserved
**
**--------------�ļ���Ϣ--------------------------------------------------------------------------------
**
** ��   ��   ��: lfs_port.h
**
** ��   ��   ��: �¿���
**
** �ļ���������: 2022 �� 06 �� 04 ��
**
** ��        ��: lfs���Ͻӿ��ļ�
*********************************************************************************************************/
#define  __SYLIXOS_STDIO
#define  __SYLIXOS_KERNEL //�������������ʹ���Ѷ�����ں˺����ͽṹ
#include "lfs.h"
#include "lfs_port.h"
#include "../../driver/mtd/nor/nor.h"
#include "SylixOS.h"
#include "../SylixOS/kernel/include/k_kernel.h"
#include "../SylixOS/system/include/s_system.h"
#include "../SylixOS/fs/fsCommon/fsCommon.h"
#include "../SylixOS/fs/include/fs_fs.h"

#ifndef LITTLEFS_DISABLE


/* Ϊ��ƥ��SylixOS����lfs_t������һ���װ��������VFS��Ҫ����Ϣ */
typedef struct lfs_volume{
    LW_DEV_HDR          LFS_devhdrHdr;                                /*  lfs�ļ�ϵͳ�豸ͷ        */
    LW_OBJECT_HANDLE    LFS_hVolLock;                                 /*  ��������                */
    LW_LIST_LINE_HEADER LFS_plineFdNodeHeader;                        /*  fd_node ����            */
    LW_LIST_LINE_HEADER LFS_plineSon;                                 /*  ��������                */
    BOOL                LFS_bForceDelete;                             /*  �Ƿ�����ǿ��ж�ؾ�       */
    BOOL                LFS_bValid;
    uid_t               LFS_uid;                                      /*  �û� id                 */
    gid_t               LFS_gid;                                      /*  ��   id                 */
    mode_t              LFS_mode;                                     /*  �ļ� mode               */
    time_t              LFS_time;                                     /*  ����ʱ��                */
    lfs_t               lfst;                                         /*  lfs�ļ�ϵͳ���          */
} LFS_VOLUME;
typedef LFS_VOLUME*     PLFS_VOLUME;

/* Ϊ��ƥ��SylixOS����dir��file���ͷ�װΪnode�ļ��ڵ㣬���������ļ�������Ϣ */
typedef struct lfs_node {
    PLFS_VOLUME         LFSN_plfs;                                      /*  �ļ�ϵͳ                    */
    BOOL                LFSN_bChanged;                                  /*  �ļ������Ƿ����             */
    mode_t              LFSN_mode;                                      /*  �ļ� mode                   */
    time_t              LFSN_timeCreate;                                /*  ����ʱ��                    */
    time_t              LFSN_timeAccess;                                /*  ������ʱ��                */
    time_t              LFSN_timeChange;                                /*  ����޸�ʱ��                */

    size_t              LFSN_stSize;                                    /*  ��ǰ�ļ���С (���ܴ��ڻ���)  */
    size_t              LFSN_stVSize;                                   /*  lseek ���������С          */
    uid_t               LFSN_uid;                                       /*  �û� id                     */
    gid_t               LFSN_gid;                                       /*  ��   id                     */
    PCHAR               LFSN_pcName;                                    /*  �ļ�����                    */
    PCHAR               LFSN_pcLink;                                    /*  ����Ŀ��                    */
    /* ���������ͣ�����isfile�жϣ�����һ��ָ��Ϊ�� */
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
static INT      __littleFsLStat();
static INT      __littleFsIoctl();
// static INT      __littleFsSymlink();
// static ssize_t  __littleFsReadlink();


/**********************************************************************************************************
*                                     �ڲ�ȫ�ֱ���/����                                                     *
***********************************************************************************************************/
const static INT BEGIN_OFF_AM29LV160DB   = 256*1024;
static       INT _G_iLittleFsDrvNum      = PX_ERROR;


/**********************************************************************************************************
*                                �ײ���������,�ļ�ϵͳĬ������                                               *
***********************************************************************************************************/

/* lfs��ײ�flash�����ݽӿ�
 * @palfs  c      �ļ�ϵͳ���ýṹ��
 * @palfs  block  ����
 * @palfs  off    ����ƫ�Ƶ�ַ
 * @palfs  buffer ���ڴ洢��ȡ��������
 * @palfs  size   Ҫ��ȡ���ֽ���
 * @return                        */
static int lfs_mini2440_read(const struct lfs_config *c, lfs_block_t block, lfs_off_t off, void *buffer, lfs_size_t size)
{
    int error = read_nor(c->block_size * block + off + BEGIN_OFF_AM29LV160DB, (PCHAR)buffer, size);
    return error;
}

/* lfs��ײ�flashд���ݽӿ�
 * @palfs  c      �ļ�ϵͳ���ýṹ��
 * @palfs  block  ����
 * @palfs  off    ����ƫ�Ƶ�ַ
 * @palfs  buffer ��д�������
 * @palfs  size   ��д�����ݵĴ�С
 * @return                        */
static int lfs_mini2440_prog(const struct lfs_config *c, lfs_block_t block, lfs_off_t off, const void *buffer, lfs_size_t size)
{
    int error = write_nor(c->block_size * block + off + BEGIN_OFF_AM29LV160DB, (PCHAR)buffer, size, WRITE_KEEP);
    return error;
}

/* lfs��ײ�flash�����ӿ�
 * @palfs  c     �ļ�ϵͳ���ýṹ��
 * @palfs  block ����
 * @return       ������         */
static int lfs_mini2440_erase(const struct lfs_config *c, lfs_block_t block)
{
    int error = erase_nor(c->block_size * block + BEGIN_OFF_AM29LV160DB, ERASE_SECTOR);
    return error;
}

/* lfs��ײ�flashͬ���ӿ�
 * @palfs  c     �ļ�ϵͳ���ýṹ��
 * @return       ������         */
static int lfs_mini2440_sync(const struct lfs_config *c)
{
    return LFS_ERR_OK;
}

const struct lfs_config cfg =            /* �ļ�ϵͳĬ�ϳ�ʼ������ */
{
    .read  = lfs_mini2440_read,
    .prog  = lfs_mini2440_prog,
    .erase = lfs_mini2440_erase,
    .sync  = lfs_mini2440_sync,

    .read_size = 4,
    .prog_size = 4,
    .block_size = 64 * 1024,
    .block_count = 28,
    .cache_size = 64 * 1024,
    .lookahead_size = 16,
    .block_cycles = 500
};

/*********************************************************************************************************
** ��������: __little_stat
** ��������: lfs ����ļ� stat
** �䡡��  : plfsn           �ļ��ڵ�
**           plfs           �ļ�ϵͳ
**           pstat          ��õ� stat
** �䡡��  : �������
** ȫ�ֱ���:
** ����ģ��:
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
** ��������: __little_statfs
** ��������: lfs ����ļ� stat
** �䡡��  : pfs           �ļ�ϵͳ
**           pstatfs          ��õ� statfs
** �䡡��  : �������
** ȫ�ֱ���:
** ����ģ��:
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


/*********************************************************************************************************
** ��������: __littleOpen
** ��������: �򿪻��ߴ����ļ�
** �䡡��  : pfs              �ڴ���littleFs�ļ�ϵͳ��super block
**           pcName           �ļ���
**           iFlags           ��ʽ
**           iMode            mode_t
** �䡡��  : < 0 ����
** ȫ�ֱ���:
** ����ģ��:
*********************************************************************************************************/
static LONG __littleFsOpen(PLFS_VOLUME     pfs,
    PCHAR           pcName,
    INT             iFlags,
    INT             iMode )
{
    PLW_FD_NODE         pfdnode;
    lfs_file_t*         plfsfile;
    lfs_dir_t*          plfsdir;
    PLFS_NODE           plfsn;
    struct stat         statGet;
    BOOL                bIsNew;

    if (pcName == LW_NULL) {
        _ErrorHandle(ERROR_IO_NO_DEVICE_NAME_IN_PATH);                  /*  ���ļ���                    */
        return  (PX_ERROR);
    }

    if (iFlags & O_CREAT) {                                             /*  ��������                    */
        if (__fsCheckFileName(pcName)) {
            _ErrorHandle(ENOENT);
            return  (PX_ERROR);
        } 
        if (S_ISFIFO(iMode) ||
            S_ISBLK(iMode) ||
            S_ISCHR(iMode) ||
            S_ISLNK(iMode)) { //TODO
            _ErrorHandle(ERROR_IO_DISK_NOT_PRESENT);                    /*  ��֧��������Щ��ʽ          */
            return  (PX_ERROR);
        }
    }

    if (__LFS_VOL_LOCK(pfs) != ERROR_NONE) {
        _ErrorHandle(ENXIO);                                            /*  �豸����                    */
        return  (PX_ERROR);
    }

    int openerr=0;
    if(S_ISDIR(iMode)){
        openerr = lfs_dir_open(&pfs->lfst, plfsdir, pcName);
        plfsn->isfile = false;
        plfsn->lfsdir = *plfsdir;
    } else{
        openerr = lfs_file_open(&pfs->lfst, plfsfile, pcName, iFlags);
        plfsn->isfile = true;
        plfsn->lfsfile = *plfsfile;
    }

    if (openerr >= 0) {
        if (!S_ISLNK(plfsn->LFSN_mode)) {
            if ((iFlags & O_CREAT) && (iFlags & O_EXCL)) {              /*  ���������ļ�                */
                __LFS_VOL_UNLOCK(pfs);
                _ErrorHandle(EEXIST);                                   /*  �Ѿ������ļ�                */
                return  (PX_ERROR);
            } else if ((iFlags & O_DIRECTORY) && !S_ISDIR(plfsn->LFSN_mode)) {
                __LFS_VOL_UNLOCK(pfs);
                _ErrorHandle(ENOTDIR);
                return  (PX_ERROR);
            }
        }
    }

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

    pfdnode->FDNODE_pvFsExtern = (PVOID)pfs;                            /*  ��¼�ļ�ϵͳ��Ϣ            */

    LW_DEV_INC_USE_COUNT(&pfs->LFS_devhdrHdr);                          /*  ���¼�����                  */
    __LFS_VOL_UNLOCK(pfs);

    return  ((LONG)pfdnode);                                            /*  �����ļ��ڵ�                */
}

/*********************************************************************************************************
** ��������: __littleFsRemove
** ��������: fs remove ����
** �䡡��  : pfs           ���豸
**           pcName           �ļ���
**           ע���ļ������Ϊ�վ���ж�ر��ļ�ϵͳ
** �䡡��  : < 0 ��ʾ����
** ȫ�ֱ���:
** ����ģ��:
*********************************************************************************************************/
static INT  __littleFsRemove (PLFS_VOLUME   pfs,
                           PCHAR         pcName)
{
//    PLW_FD_NODE         pfdnode;
    lfs_file_t* plfsfile;
    lfs_dir_t* plfsdir;
    PLFS_NODE plfsn;

    // BOOL       bRoot;
    // PCHAR      pcTail;
    // INT        iError;

    if (pcName == LW_NULL) {
        _ErrorHandle(ERROR_IO_NO_DEVICE_NAME_IN_PATH);
        return  (PX_ERROR);
    }

    if (__LFS_VOL_LOCK(pfs) != ERROR_NONE) {
        _ErrorHandle(ENXIO);                                            /*  �豸����                    */
        return  (PX_ERROR);
    }

    struct lfs_info* lfsinfo;
    int error=lfs_stat(&pfs->lfst,pcName,lfsinfo);
    if(!error){
        if(lfsinfo->type==LFS_TYPE_DIR){
            lfs_dir_open(&pfs->lfst,plfsdir,pcName);
            plfsn->isfile=false;
            plfsn->lfsdir=*plfsdir;
        }
        else{
            lfs_file_open(&pfs->lfst,plfsfile,pcName,LFS_O_RDWR);
            plfsn->isfile=true;
            plfsn->lfsfile=*plfsfile;
        }
    }else{
        __LFS_VOL_UNLOCK(pfs);
        _ErrorHandle(ENOENT);
        return  (PX_ERROR);
    }

    if (plfsfile||plfsdir) {
        lfs_remove(&pfs->lfst,pcName);
        __LFS_VOL_UNLOCK(pfs);
        return  (ERROR_NONE);

    } else if (!pcName) {                                                 /*  ɾ�� lfs �ļ�ϵͳ         */
        if (pfs->LFS_bValid == LW_FALSE) {
            __LFS_VOL_UNLOCK(pfs);
            return  (ERROR_NONE);                                       /*  ���ڱ���������ж��          */
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
        iosDevFileAbnormal(&pfs->LFS_devhdrHdr);               /*  ����������ļ���Ϊ�쳣ģʽ  */

        __LFS_VOL_LOCK(pfs);
        goto    __re_umount_vol;

    } else {
        pfs->LFS_bValid = LW_FALSE;
    }

        iosDevDelete((LW_DEV_HDR *)pfs);                             /*  IO ϵͳ�Ƴ��豸             */
        API_SemaphoreMDelete(&pfs->LFS_hVolLock);

        lfs_unmount(&pfs->lfst);                                          /*  �ͷ������ļ�����            */
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
** ��������: __littleFsClose
** ��������: fs close ����
** �䡡��  : pfdentry         �ļ����ƿ�
** �䡡��  : < 0 ��ʾ����
** ȫ�ֱ���:
** ����ģ��:
*********************************************************************************************************/
static INT  __littleFsClose (PLW_FD_ENTRY    pfdentry)
{
    PLW_FD_NODE   pfdnode = (PLW_FD_NODE)pfdentry->FDENTRY_pfdnode;
    PLFS_NODE     plfsn   = (PLFS_NODE)pfdnode->FDNODE_pvFile;
    PLFS_VOLUME   pfs  = (PLFS_VOLUME)pfdnode->FDNODE_pvFsExtern;
    BOOL          bRemove = LW_FALSE;

    if (__LFS_VOL_LOCK(pfs) != ERROR_NONE) {
        _ErrorHandle(ENXIO);                                            /*  �豸����                    */
        return  (PX_ERROR);
    }

    if (API_IosFdNodeDec(&pfs->LFS_plineFdNodeHeader,
                         pfdnode, &bRemove) == 0) {
        if (plfsn->isfile) {
            lfs_dir_close(&pfs->lfst, &plfsn->lfsdir);
        }else{
            lfs_file_close(&pfs->lfst, &plfsn->lfsfile);
        }
    }

    LW_DEV_DEC_USE_COUNT(&pfs->LFS_devhdrHdr);

    __LFS_VOL_UNLOCK(pfs);

    return  (ERROR_NONE);
}

/*********************************************************************************************************
** ��������: __littleFsRead
** ��������: fs read ����
** �䡡��  : pfdentry         �ļ����ƿ�
**           pcBuffer         ���ջ�����
**           stMaxBytes       ���ջ�������С
** �䡡��  : �������
** ȫ�ֱ���:
** ����ģ��:
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
                pfdentry->FDENTRY_oftPtr += (off_t)sstReadNum;              /*  �����ļ�ָ��                */
            }
        }
    } else {
        sstReadNum = 0;
    }

    __LFS_FILE_UNLOCK(plfsn);

    return  (sstReadNum);
}

/*********************************************************************************************************
** ��������: __littleFsPRead
** ��������: fs pread ����
** �䡡��  : pfdentry         �ļ����ƿ�
**           pcBuffer         ���ջ�����
**           stMaxBytes       ���ջ�������С
**           oftPos           λ��
** �䡡��  : �������
** ȫ�ֱ���:
** ����ģ��:
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
                pfdentry->FDENTRY_oftPtr += (off_t)sstReadNum;              /*  �����ļ�ָ��                */
            }
        }

    } else {
        sstReadNum = 0;
    }

    __LFS_FILE_UNLOCK(plfsn);

    return  (sstReadNum);
}

/*********************************************************************************************************
** ��������: __littleFsWrite
** ��������: fs write ����
** �䡡��  : pfdentry         �ļ����ƿ�
**           pcBuffer         ������
**           stNBytes         ��Ҫд�������
** �䡡��  : �������
** ȫ�ֱ���:
** ����ģ��:
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

    if (pfdentry->FDENTRY_iFlag & O_APPEND) {                           /*  ׷��ģʽ                    */
        pfdentry->FDENTRY_oftPtr = pfdnode->FDNODE_oftSize;             /*  �ƶ���дָ�뵽ĩβ          */
    }

    if (stNBytes) {
        if(!plfsn->isfile){
            _DebugHandle(__LOGMESSAGE_LEVEL, "LittleFS: you can not write a directory.\r\n");
        }else{
            sstWriteNum = lfs_file_write(&plfsn->LFSN_plfs->lfst, &plfsn->lfsfile, pcBuffer, stNBytes);
        }
        if (sstWriteNum > 0) {
                pfdentry->FDENTRY_oftPtr += (off_t)sstWriteNum;             /*  �����ļ�ָ��                */
                pfdnode->FDNODE_oftSize   = (off_t)plfsn->LFSN_stSize;
        }
    } else {
        sstWriteNum = 0;
    }

    __LFS_FILE_UNLOCK(plfsn);

    return  (sstWriteNum);
}

/*********************************************************************************************************
** ��������: __littleFsPWrite
** ��������: fs pwrite ����
** �䡡��  : pfdentry         �ļ����ƿ�
**           pcBuffer         ������
**           stNBytes         ��Ҫд�������
**           oftPos           λ��
** �䡡��  : �������
** ȫ�ֱ���:
** ����ģ��:
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
                pfdentry->FDENTRY_oftPtr += (off_t)sstWriteNum;             /*  �����ļ�ָ��                */
                pfdnode->FDNODE_oftSize   = (off_t)plfsn->LFSN_stSize;
        }
    } else {
        sstWriteNum = 0;
    }

    __LFS_FILE_UNLOCK(plfsn);

    return  (sstWriteNum);
}

/*********************************************************************************************************
** ��������: __littleFsNRead
** ��������: lfsFs nread ����
** �䡡��  : pfdentry         �ļ����ƿ�
**           piNRead          ʣ��������
** �䡡��  : �������
** ȫ�ֱ���:
** ����ģ��:
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
** ��������: __littleFsNRead64
** ��������: lfsFs nread ����
** �䡡��  : pfdentry         �ļ����ƿ�
**           poftNRead        ʣ��������
** �䡡��  : �������
** ȫ�ֱ���:
** ����ģ��:
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
** ��������: __littleFsSeek
** ��������: lfsFs seek ����
** �䡡��  : pfdentry         �ļ����ƿ�
**           oftOffset        ƫ����
** �䡡��  : �������
** ȫ�ֱ���:
** ����ģ��:
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
** ��������: __littleFsWhere
** ��������: lfsFs ����ļ���ǰ��дָ��λ�� (ʹ�ò�����Ϊ����ֵ, �� FIOWHERE ��Ҫ�����в�ͬ)
** �䡡��  : pfdentry            �ļ����ƿ�
**           poftPos             ��дָ��λ��
** �䡡��  : < 0 ��ʾ����
** ȫ�ֱ���:
** ����ģ��:
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
** ��������: __littleFsStatGet
** ��������: lfsFs stat ����
** �䡡��  : pfdentry         �ļ����ƿ�
**           pstat            �ļ�״̬
** �䡡��  : < 0 ��ʾ����
** ȫ�ֱ���:
** ����ģ��:
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
** ��������: __littleFsStatfs
** ��������: lfsFs statfs ����
** �䡡��  : pfdentry         �ļ����ƿ�
**           pstatfs          �ļ�ϵͳ״̬
** �䡡��  : < 0 ��ʾ����
** ȫ�ֱ���:
** ����ģ��:
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
** ��������: __littleFsTimeset
** ��������: fs �����ļ�ʱ��
** �䡡��  : pfdentry            �ļ����ƿ�
**           utim                utimbuf �ṹ
** �䡡��  : < 0 ��ʾ����
** ȫ�ֱ���:
** ����ģ��:
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
** ��������: __littleFsIoctl
** ��������: lfsFs ioctl ����
** �䡡��  : pfdentry           �ļ����ƿ�
**           request,           ����
**           arg                �������
** �䡡��  : < 0 ��ʾ����
** ȫ�ֱ���:
** ����ģ��:
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

    case FIODISKINIT:                                                   /*  ���̳�ʼ��                  */
        return  (ERROR_NONE);

    case FIOSEEK:                                                       /*  �ļ��ض�λ                  */
        oftTemp = *(off_t *)lArg;
        return  (__littleFsSeek(pfdentry, oftTemp));

    case FIOWHERE:                                                      /*  ����ļ���ǰ��дָ��        */
        iError = __littleFsWhere(pfdentry, &oftTemp);
        if (iError == PX_ERROR) {
            return  (PX_ERROR);
        } else {
            *(off_t *)lArg = oftTemp;
            return  (ERROR_NONE);
        }

    case FIONREAD:                                                      /*  ����ļ�ʣ���ֽ���          */
        return  (__littleFsNRead(pfdentry, (INT *)lArg));

    case FIONREAD64:                                                    /*  ����ļ�ʣ���ֽ���          */
        iError = __littleFsNRead64(pfdentry, &oftTemp);
        if (iError == PX_ERROR) {
            return  (PX_ERROR);
        } else {
            *(off_t *)lArg = oftTemp;
            return  (ERROR_NONE);
        }

//    case FIORENAME:                                                     /*  �ļ�������                  */
//        return  (__littleFsRename(pfdentry, (PCHAR)lArg));
//
    case FIOLABELGET:                                                   /*  ��ȡ����                    */
    case FIOLABELSET:                                                   /*  ���þ���                    */
        _ErrorHandle(ENOSYS);
        return  (PX_ERROR);

    case FIOFSTATGET:                                                   /*  ����ļ�״̬                */
        return  (__littleFsStat(pfdentry, (struct stat *)lArg));

    case FIOFSTATFSGET:                                                 /*  ����ļ�ϵͳ״̬            */
        return  (__littleFsStatfs(pfdentry, (struct statfs *)lArg));

//    case FIOREADDIR:                                                    /*  ��ȡһ��Ŀ¼��Ϣ            */
//        return  (__littleFsReadDir(pfdentry, (DIR *)lArg));

    case FIOTIMESET:                                                    /*  �����ļ�ʱ��                */
        return  (__littleFsTimeset(pfdentry, (struct utimbuf *)lArg));

//    case FIOTRUNC:                                                      /*  �ı��ļ���С                */
//        oftTemp = *(off_t *)lArg;
//        return  (__littleFsTruncate(pfdentry, oftTemp));

    case FIOSYNC:                                                       /*  ���ļ������д              */
    case FIOFLUSH:
    case FIODATASYNC:
        return  (ERROR_NONE);

//    case FIOCHMOD:
//        return  (__littleFsChmod(pfdentry, (INT)lArg));                    /*  �ı��ļ�����Ȩ��            */

    case FIOSETFL:                                                      /*  �����µ� flag               */
        if ((INT)lArg & O_NONBLOCK) {
            pfdentry->FDENTRY_iFlag |= O_NONBLOCK;
        } else {
            pfdentry->FDENTRY_iFlag &= ~O_NONBLOCK;
        }
        return  (ERROR_NONE);
//
//    case FIOCHOWN:                                                      /*  �޸��ļ�������ϵ            */
//        return  (__littleFsChown(pfdentry, (LW_IO_USR *)lArg));

    case FIOFSTYPE:                                                     /*  ����ļ�ϵͳ����            */
        *(PCHAR *)lArg = "littleFS FileSystem";
        return  (ERROR_NONE);

    case FIOGETFORCEDEL:                                                /*  ǿ��ж���豸�Ƿ�����      */
        *(BOOL *)lArg = pfs->LFS_bForceDelete;
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


/*********************************************************************************************************
                                           API ����
** ��������: API_LittleFsDrvInstall
** ��������: ��װ lfs �ļ�ϵͳ��������
** �䡡��  :
** �䡡��  : < 0 ��ʾʧ��
** ȫ�ֱ���:
** ����ģ��:
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

    _G_iLittleFsDrvNum = iosDrvInstallEx2(&fileop, LW_DRV_TYPE_NEW_1);     /*  ʹ�� NEW_1 ���豸��������   */

    DRIVER_LICENSE(_G_iLittleFsDrvNum, "GPL->Ver 2.0");
    DRIVER_AUTHOR (_G_iLittleFsDrvNum, "Junwen Zhang");
    DRIVER_DESCRIPTION(_G_iLittleFsDrvNum, "LittleFs driver.");

    _DebugHandle(__LOGMESSAGE_LEVEL, "LittleFs installed.\r\n");

    __fsRegister("lfs", API_LittleFsDevCreate, LW_NULL, LW_NULL);        /*  ע���ļ�ϵͳ                */

    return  ((_G_iLittleFsDrvNum > 0) ? (ERROR_NONE) : (PX_ERROR));
}

/*********************************************************************************************************
** ��������: API_LittleFsDevCreate
** ��������: ���� lfs �ļ�ϵͳ�豸.
** �䡡��  : pcName            �豸��(�豸�ҽӵĽڵ��ַ)
** �䡡��  : < 0 ��ʾʧ��
** ȫ�ֱ���:
** ����ģ��:
                                           API ����
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

    pfs = (PLFS_VOLUME)lib_malloc(sizeof(LFS_VOLUME));
    if (pfs == LW_NULL) {
        _DebugHandle(__ERRORMESSAGE_LEVEL, "LittleFS: system low memory.\r\n");
        _ErrorHandle(ERROR_SYSTEM_LOW_MEMORY);
        return  (PX_ERROR);
    }
    lib_bzero(pfs, sizeof(LFS_VOLUME));                              /*  ��վ����ƿ�                */

    pfs->LFS_bValid = LW_TRUE;

    pfs->LFS_hVolLock = API_SemaphoreMCreate("LittleFS: lfs_volume_lock", LW_PRIO_DEF_CEILING,
        LW_OPTION_WAIT_PRIORITY | LW_OPTION_DELETE_SAFE |
        LW_OPTION_INHERIT_PRIORITY | LW_OPTION_OBJECT_GLOBAL,
        LW_NULL);

    if (!pfs->LFS_hVolLock) {                                       /*  �޷���������                */
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
        != ERROR_NONE) {                                                /*  ��װ�ļ�ϵͳ�豸            */
        API_SemaphoreMDelete(&pfs->LFS_hVolLock);
        free(pfs);
        return  (PX_ERROR);
    }

    _DebugFormat(__LOGMESSAGE_LEVEL, "LittleFS: target \"%s\" mount ok.\r\n", pcName);
    return  (ERROR_NONE);
}

/*********************************************************************************************************
** ��������: API_LittleFsDevDelete
** ��������: ɾ��һ�� lfs �ļ�ϵͳ�豸, ����: API_LittleFsDevDelete("/mnt/lfs0");
** �䡡��  : pcName            �ļ�ϵͳ�豸��(�����豸�ҽӵĽڵ��ַ)
** �䡡��  : < 0 ��ʾʧ��
** ȫ�ֱ���:
** ����ģ��:
                                           API ����
*********************************************************************************************************/
LW_API INT  API_LittleFsDevDelete(PCHAR   pcName)
{
    if (API_IosDevMatchFull(pcName)) {                                  /*  ������豸, �����ж���豸  */
        return  (unlink(pcName));

    }
    else {
        _ErrorHandle(ENOENT);
        return  (PX_ERROR);
    }
}

#endif