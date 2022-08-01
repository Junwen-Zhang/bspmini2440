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
    LW_OBJECT_HANDLE    LFS_hVolLock;                                 /*  �������                        */
    LW_LIST_LINE_HEADER LFS_plineFdNodeHeader;                        /*  fd_node ����               */

    BOOL                LFS_bForceDelete;                             /*  �Ƿ�����ǿ��ж�ؾ�      */
    BOOL                LFS_bValid;

    uid_t               LFS_uid;                                      /*  �û� id             */
    gid_t               LFS_gid;                                      /*  ��   id              */
    mode_t              LFS_mode;                                     /*  �ļ� mode           */
    time_t              LFS_time;                                     /*  ����ʱ��                        */
    lfs_t               lfst;                                         /*  lfs�ļ�ϵͳ���           */
} LFS_VOLUME;
typedef LFS_VOLUME*     PLFS_VOLUME;

/* Ϊ��ƥ��SylixOS����dir��file���ͷ�װΪnode�ļ��ڵ㣬���������ļ�������Ϣ */
typedef struct lfs_node {
    PLFS_VOLUME         LFSN_plfs;                                      /*       �ļ�ϵͳ               */

    BOOL                LFSN_bChanged;                                  /*       �ļ������Ƿ����        */
    mode_t              LFSN_mode;                                      /*       �ļ� mode              */
    time_t              LFSN_timeCreate;                                /*       ����ʱ��               */
    time_t              LFSN_timeAccess;                                /*       ������ʱ��            */
    time_t              LFSN_timeChange;                                /*       ����޸�ʱ��            */

    size_t              LFSN_stSize;                                    /*  ��ǰ�ļ���С (���ܴ��ڻ���)   */
    size_t              LFSN_stVSize;                                   /*      lseek ���������С       */

    uid_t               LFSN_uid;                                       /*         �û� id              */
    gid_t               LFSN_gid;                                       /*         ��   id              */
    
    // PCHAR               LFSN_pcLink;                                 /*         ����Ŀ��              */
    /* ���������ͣ�����isfile�жϣ�lfsdir��lfsfile����һ��Ϊ�� */
    bool                isfile;
    lfs_dir_t           lfsdir;
    lfs_file_t          lfsfile;
} LFS_NODE;
typedef LFS_NODE*       PLFS_NODE;


/* �����ļ��򿪱�ǵ�ת����������дȨ�ޣ��Ƿ񴴽��� */
int mode_lfs2sylix(int lfsmode){
    int temp = 0;
    if (lfsmode & LFS_O_RDONLY)    temp |= O_RDONLY;
    if (lfsmode & LFS_O_WRONLY)    temp |= O_WRONLY;
    if (lfsmode & LFS_O_RDWR)      temp |= O_RDWR;
    if (lfsmode & LFS_O_CREAT)     temp |= O_CREAT;
    return temp;
}
int mode_sylix2lfs(int sylixmode){
    int temp = 0;
    if(sylixmode == O_RDONLY)   temp |= LFS_O_RDONLY;
    if(sylixmode & O_WRONLY)    temp |= LFS_O_WRONLY;
    if(sylixmode & O_RDWR)      temp |= LFS_O_RDWR;
    if(sylixmode & O_CREAT)     temp |= LFS_O_CREAT;
    return temp;
}

/* �����ļ����͵�ת�� */
int type_lfs2sylix(int lfstype){
    int temp = 0;
    if (lfstype & LFS_TYPE_REG)    temp |= S_IFREG;
    if (lfstype & LFS_TYPE_DIR)    temp |= S_IFDIR;
    return temp;
}

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

//static uint8_t lfs_read_buf[256];
//static uint8_t lfs_prog_buf[256];
//static uint8_t lfs_lookahead_buf[16];

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
    .cache_size = 256,
    .lookahead_size = 16,
    .block_cycles = 500,
//
//    .read_buffer = lfs_read_buf,
//    .prog_buffer = lfs_prog_buf,
//    .lookahead_buffer = lfs_lookahead_buf
};

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
** ��������: __little_stat
** ��������: lfs ����ļ� stat
** �䡡��  : plfsn           �ļ��ڵ�
**           plfs           �ļ�ϵͳ
**           pstat          ��õ� stat
** �䡡��  : �������
** ȫ�ֱ���:
** ����ģ��:
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
** ��������: __little_statfs
** ��������: lfs ����ļ� stat
** �䡡��  : pfs           �ļ�ϵͳ
**           pstatfs          ��õ� statfs
** �䡡��  : �������
** ȫ�ֱ���:
** ����ģ��:
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

/* �����ڵ㣬���򿪣���Ϣ������plfsn�з��� */
static inline PLFS_NODE __lfs_maken (PLFS_VOLUME plfs,
                                     PCHAR       pcName,
                                     INT         iFlag,
                                     mode_t      mode)
{
    int err = 0;

    PLFS_NODE plfsn = (PLFS_NODE)__SHEAP_ALLOC(sizeof(LFS_NODE)); /*   �����ڴ棬�����ڵ�    */
    if (plfsn == LW_NULL){
        _ErrorHandle(ENOMEM);
        return  (NULL);
    }
    lib_bzero(plfsn,sizeof(LFS_NODE));                            /*       �ڵ����         */

    if(S_ISDIR(mode)){
        err = lfs_mkdir(&plfs->lfst, pcName);                     /*     ��������(Ŀ¼)      */
        if(err >= 0) {
            // printf("__lfs_maken(): lfs_mkdir sucess!\r\n");
            err = lfs_dir_open(&plfs->lfst, &plfsn->lfsdir, pcName);
            if(err >= 0){
                // printf("__lfs_maken(): lfs_dir_open sucess!\r\n");
                __lfs_init_plfsn(plfsn, plfs, mode|S_IFDIR);
                plfsn->isfile = false;
            }
        }
    }else{                                                        /*     ��������(�ļ�)      */
        err = lfs_file_open(&plfs->lfst, &plfsn->lfsfile, pcName,
                            mode_sylix2lfs(iFlag)|LFS_O_CREAT);
        if(err >= 0){
            // printf("__lfs_maken(): lfs_file_open with create sucess!\r\n");
            __lfs_init_plfsn(plfsn, plfs, mode|S_IFREG);
            plfsn->isfile = true;
        }
    }

    if (err < 0) {
        __SHEAP_FREE(plfsn);
        // printf("__lfs_maken(): failed ! \r\n");
        return NULL;
    }
    return  plfsn;
}

/* �����Ĵ��ļ���Ŀ¼�����ڵ㲻���ڲ��ᴴ���ڵ� */
static inline PLFS_NODE __lfs_open (PLFS_VOLUME pfs,
                                    PCHAR       pcName,
                                    INT         iFlags,
                                    INT         iMode)
{
    int err = 0;

    if (iFlags & O_CREAT){
        // printf("in func(__lfs_open), node can't be made.\r\n");
        return (NULL);
    }

    PLFS_NODE plfsn = (PLFS_NODE)__SHEAP_ALLOC(sizeof(LFS_NODE)); /*   �����ڴ棬�����ڵ�    */
    if (plfsn == LW_NULL){
        _ErrorHandle(ENOMEM);
        return  (NULL);
    }
    lib_bzero(plfsn,sizeof(LFS_NODE));                            /*       �ڵ����         */
    
    /* ���ﲻ��iMode�ж��ļ�����Ŀ¼������Ϊ��ʱ��Ϣδ��ȡ��iModeδ֪��*/
    err = lfs_file_open(&pfs->lfst, &plfsn->lfsfile, 
                                pcName, mode_sylix2lfs(iFlags));
    if(err >= 0){
        plfsn->isfile = true;
        __lfs_init_plfsn(plfsn, pfs, iMode|S_IFREG);
        // printf("lfs_file_open() success!\r\n");
    }else{
        err = lfs_dir_open(&pfs->lfst, &plfsn->lfsdir, pcName);
        if(err >= 0){
            plfsn->isfile = false;
            __lfs_init_plfsn(plfsn, pfs, iMode|S_IFDIR);
            // printf("lfs_dir_open() success!\r\n");
        }
    }

    if (err < 0) {
        __SHEAP_FREE(plfsn);
        // printf("_lfs_open() failed!\r\n\r\n");
        return NULL;
    }

    // printf("_lfs_open() end, plfsn: %p  %d !\r\n\r\n",plfsn,(int)plfsn);
    return plfsn;
}

/* ɾ��һ���ļ����ļ��нڵ� */
static inline INT  __lfs_unlink (PLFS_NODE  plfsn)
{
    PLFS_VOLUME     plfs   = plfsn->LFSN_plfs;
    
    if (plfsn!=NULL && plfsn!=PX_ERROR && S_ISDIR(plfsn->LFSN_mode)) {                                  /*    �ļ�����Ҫɾ��������Ϊ��    */
        lfs_dir_rewind(&plfs->lfst, &plfsn->lfsdir);
        struct lfs_info infotemp;
        int err = lfs_dir_read(&plfs->lfst, &plfsn->lfsdir, &infotemp);
        if(err > 0) {
            // printf("__lfs_unlink(): the dir is not empty, and can't move!\r\n");
            return (PX_ERROR);
        }else{
            // printf("__lfs_unlink: dir remove success!\r\n");
        }
    }

    __SHEAP_FREE(plfsn);
    // printf("__lfs_unlink() end!\r\n\r\n");
    return  (ERROR_NONE);
}


/*********************************************************************************************************
** ��������: __littleOpen
** ��������: �򿪻��ߴ����ļ�
** �䡡��  :  pfs              �ڴ���littleFs�ļ�ϵͳ��super block
**           pcName           �ļ���
**           iFlags           �򿪱�־�������дȨ�ޣ��Ƿ񴴽�
**           iMode            mode_t���ļ�������
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
    PLFS_NODE           plfsn;
    struct stat         statGet;
    BOOL                bIsNew;
    int                 bCreate;

    if (pcName == LW_NULL) {                                             /*        ���ļ���              */
        _ErrorHandle(ERROR_IO_NO_DEVICE_NAME_IN_PATH);
        return  (PX_ERROR);
    }

    if (iFlags & O_CREAT) {                                             /*         ��������             */
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

    if (__LFS_VOL_LOCK(pfs) != ERROR_NONE) {                             /*         �豸����            */
        _ErrorHandle(ENXIO);                                             
        return  (PX_ERROR);
    }


    /************************************ TODO ************************************/

    /* �����ж��Ƿ����ļ�ϵͳ��Ŀ¼ */
    bool broot = FALSE;
    if (*pcName == PX_ROOT) {                                          /*         ���Ը�����           */
        if (pcName[1] == PX_EOS) broot= TRUE;
        else broot = FALSE;
    } else {
        if (pcName[0] == PX_EOS) broot= TRUE;
        else broot = FALSE;
    }

    plfsn = __lfs_open(pfs, pcName, iFlags, iMode);                    /*    �ԷǴ�������ʽ���ļ�     */
    // printf("plfsn:%d\n",(int)plfsn);

    if (!plfsn){
        if (iFlags & O_CREAT){                                         /*      �ļ������ڣ��򴴽�       */
            if (__fsCheckFileName(pcName)) {
                // printf("open with make, __fsCheckFileName() failed!\r\n");
                _ErrorHandle(ENOENT);
                return  (PX_ERROR);
            }
            plfsn = __lfs_maken(pfs, pcName, iFlags, iMode);           /*     �����ļ���Ŀ¼�ڵ�       */
            if ( plfsn == NULL ) {
                // printf("in __LittleFsOpen(), _fs_maken failed!\r\n");
                return  (PX_ERROR);
            } else{
                // printf("in __LittleFsOpen(), _fs_maken success!\r\n");
            }
        }else{
            __LFS_VOL_UNLOCK(pfs);
            // printf("__littleFsOpen() end without a node add ############################\r\n\r\n");
            return  (PX_ERROR);
        }
    }
             

    __lfs_stat(plfsn, pfs, &statGet);
    pfdnode = API_IosFdNodeAdd(&pfs->LFS_plineFdNodeHeader,            /*        ����ļ��ڵ�          */
                               statGet.st_dev,
                               (ino64_t)statGet.st_ino,
                               iFlags,
                               plfsn->LFSN_mode,
                               statGet.st_uid,
                               statGet.st_gid,
                               statGet.st_size,
                               (PVOID)plfsn,
                               &bIsNew);
    
    if (pfdnode == LW_NULL) {                                           /*     �޷����� fd_node �ڵ�    */
        __LFS_VOL_UNLOCK(pfs);
        __lfs_unlink(plfsn);                                            /*       ɾ���½��Ľڵ�         */
        return  (PX_ERROR);
    }
    pfdnode->FDNODE_pvFsExtern = (PVOID)pfs;                            /*      ��¼�ļ�ϵͳ��Ϣ        */

    if ((iFlags & O_TRUNC) && ((iFlags & O_ACCMODE) != O_RDONLY)) {     /*         ��Ҫ�ض�             */
        if ( plfsn ) {
            // __ram_truncate(pramn, 0); //TODO
            pfdnode->FDNODE_oftSize = 0;
        }
    }

    LW_DEV_INC_USE_COUNT(&pfs->LFS_devhdrHdr);                          /*        ���¼�����            */

    __LFS_VOL_UNLOCK(pfs);
    // printf("__littleFsOpen end and add node ############################\r\n\r\n");
    return  (pfdnode);                                                  /*        �����ļ��ڵ�          */
}

/*********************************************************************************************************
** ��������: __littleFsRemove
** ��������: fs remove ����
** �䡡��  :  pfs           ���豸
**           pcName         �ļ���
**           ע���ļ������Ϊ�վ���ж�ر��ļ�ϵͳ
** �䡡��  : < 0 ��ʾ����
** ȫ�ֱ���:
** ����ģ��:
*********************************************************************************************************/
static INT  __littleFsRemove (PLFS_VOLUME   pfs,
                           PCHAR         pcName)
{
    if (pcName == LW_NULL) {
        _ErrorHandle(ERROR_IO_NO_DEVICE_NAME_IN_PATH);
        return  (PX_ERROR);
    }

    if (__LFS_VOL_LOCK(pfs) != ERROR_NONE) {
        _ErrorHandle(ENXIO);                                            /*  �豸����                    */
        return  (PX_ERROR);
    }

    /* �����ж��Ƿ����ļ�ϵͳ��Ŀ¼ */
    bool broot = FALSE;
    if (*pcName == PX_ROOT) {                                           /*  ���Ը�����                  */
        if (pcName[1] == PX_EOS) broot= TRUE;
        else broot = FALSE;
    } else {
        if (pcName[0] == PX_EOS) broot= TRUE;
        else broot = FALSE;
    }

    int err;
    if (broot == FALSE){
        err = lfs_remove(&pfs->lfst, pcName);                           /*        ɾ�� lfs �ļ�         */
        __LFS_VOL_UNLOCK(pfs);
        return  (err);
    } else {                                                            /*       ɾ�� lfs �ļ�ϵͳ       */
        if (pfs->LFS_bValid == LW_FALSE) {
            __LFS_VOL_UNLOCK(pfs);
            return  (ERROR_NONE);                                       /*      ���ڱ���������ж��        */
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
        iosDevFileAbnormal(&pfs->LFS_devhdrHdr);                          /*  ����������ļ���Ϊ�쳣ģʽ  */

        __LFS_VOL_LOCK(pfs);
        goto __re_umount_vol;

    } else {
        pfs->LFS_bValid = LW_FALSE;
    }

        iosDevDelete((LW_DEV_HDR *)pfs);                                  /*      IO ϵͳ�Ƴ��豸             */
        API_SemaphoreMDelete(&pfs->LFS_hVolLock);

        lfs_unmount(&pfs->lfst);                                          /*      �ͷ������ļ�����            */
        __SHEAP_FREE(pfs);

        _DebugHandle(__LOGMESSAGE_LEVEL, "LittleFS: Lfs unmount ok.\r\n");

        return  (ERROR_NONE);
    } 

}

/*********************************************************************************************************
** ��������: __littleFsClose
** ��������: fs close ����
** �䡡��  : pfdentry         �ļ����ƿ�
** �䡡��  : < 0              ��ʾ����
** ȫ�ֱ���:
** ����ģ��:
*********************************************************************************************************/
static INT  __littleFsClose (PLW_FD_ENTRY    pfdentry)
{
    PLW_FD_NODE   pfdnode = (PLW_FD_NODE)pfdentry->FDENTRY_pfdnode ;
    PLFS_NODE     plfsn   = (PLFS_NODE)  pfdnode->FDNODE_pvFile    ;
    PLFS_VOLUME   pfs     = (PLFS_VOLUME)pfdnode->FDNODE_pvFsExtern;
    BOOL          bRemove = LW_FALSE;   //TODO

    if (__LFS_VOL_LOCK(pfs) != ERROR_NONE) {                              /*        �豸����            */
        _ErrorHandle(ENXIO);                                           
        return  (PX_ERROR);
    }

    if (API_IosFdNodeDec(&pfs->LFS_plineFdNodeHeader,
                         pfdnode, &bRemove) == 0) {
        if (plfsn) 
        if (plfsn->isfile){
            lfs_file_close(&pfs->lfst, &plfsn->lfsfile);
        }else{
            lfs_dir_close(&pfs->lfst, &plfsn->lfsdir);
        }
    }

    LW_DEV_DEC_USE_COUNT(&pfs->LFS_devhdrHdr);

    if (bRemove && plfsn) __lfs_unlink(plfsn);

    __LFS_VOL_UNLOCK(pfs);

    // printf("__littleFsClose end ################## \r\n\r\n");
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
            _DebugHandle(__LOGMESSAGE_LEVEL, "LittleFS: you can not read a directory.\r\n");
        }else{
            sstReadNum = lfs_file_read(&plfsn->LFSN_plfs->lfst, &plfsn->lfsfile, pcBuffer, stMaxBytes);
            if (sstReadNum > 0) {
                pfdentry->FDENTRY_oftPtr += (off_t)sstReadNum;              /*  �����ļ�ָ��                */
                lfs_file_seek(&plfsn->LFSN_plfs->lfst, &plfsn->lfsfile,sstReadNum,LFS_SEEK_CUR);
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
                pfdentry->FDENTRY_oftPtr += (off_t)sstWriteNum;        /*  �����ļ�ָ��                */
                lfs_file_seek(&plfsn->LFSN_plfs->lfst, &plfsn->lfsfile,sstWriteNum,LFS_SEEK_CUR);
                pfdnode->FDNODE_oftSize   = lfs_file_size(&plfsn->LFSN_plfs->lfst, &plfsn->lfsfile);
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
                lfs_file_seek(&plfsn->LFSN_plfs->lfst, &plfsn->lfsfile,sstWriteNum,LFS_SEEK_CUR);
                pfdnode->FDNODE_oftSize   = lfs_file_size(&plfsn->LFSN_plfs->lfst, &plfsn->lfsfile);
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
** ��������: __littleFsStat
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
** ��������: __littleFsLStat
** ��������: littleFs stat ����, ͨ���ļ�����ȡ�ļ�״̬ 
** �䡡��  : pfs               lfs �ļ�ϵͳ
**           pcName           �ļ���
**           pstat            �ļ�״̬
** �䡡��  : < 0 ��ʾ����
** ȫ�ֱ���:
** ����ģ��:
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
    } else if (pcName[0] == PX_EOS) {                                /* �ļ�ϵͳ��Ŀ¼ */
        __lfs_stat(LW_NULL, pfs, pstat);
    } else {
        __LFS_VOL_UNLOCK(pfs);
        _ErrorHandle(ENOENT);
        return  (PX_ERROR);        
    }

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

    return  (ERROR_NONE);
}

/*********************************************************************************************************
** ��������: __littleFsReadDir
** ��������: littleFs ���ָ��Ŀ¼��Ϣ
** �䡡��  : pfdentry            �ļ����ƿ�
**           dir                 Ŀ¼�ṹ
** �䡡��  : < 0 ��ʾ����
** ȫ�ֱ���:
** ����ģ��:
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
        // printf("ERROR: plfsn is NULL!\r\n");
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
            // printf("dir read success in %d! %d\r\n",plfsn->lfsdir.pos,dirreaderr);
        }else if(dirreaderr<0){
            // printf("ERROR: dir read fail in %d! type:%08x\r\n",plfsn->lfsdir.pos,lfsdirinfo.type);
            __LFS_VOL_UNLOCK(plfs);
            return (PX_ERROR);
        }else{
            _ErrorHandle(ENOENT);                               /*  û�ж���Ľڵ�              */
            __LFS_VOL_UNLOCK(plfs);
            return (PX_ERROR);
        }
    }else{
        // printf("ERROR: plfsn is a file!\r\n");
        __LFS_VOL_UNLOCK(plfs);
        return (PX_ERROR);
    }

    // printf("dir->dir_pos: %ld", dir->dir_pos);
    dir->dir_pos++;
    
    lib_strlcpy(dir->dir_dirent.d_name, 
                lfsdirinfo.name,
                sizeof(dir->dir_dirent.d_name));
                
    dir->dir_dirent.d_type = type_lfs2sylix(lfsdirinfo.type);
    dir->dir_dirent.d_shortname[0] = PX_EOS;

    __LFS_VOL_UNLOCK(plfs);
    
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

    case FIODISKINIT:                                                   /*  ���̳�ʼ��                         */
        return  (ERROR_NONE);

    case FIOSEEK:                                                       /*  �ļ��ض�λ                         */
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

//    case FIORENAME:                                                   /*  �ļ�������                  */
//        return  (__littleFsRename(pfdentry, (PCHAR)lArg));
//
    case FIOLABELGET:                                                   /*  ��ȡ���                    */
    case FIOLABELSET:                                                   /*  ���þ��                    */
        _ErrorHandle(ENOSYS);
        return  (PX_ERROR);

    case FIOFSTATGET:                                                   /*  ����ļ�״̬                */
        return  (__littleFsStat(pfdentry, (struct stat *)lArg));

    case FIOFSTATFSGET:                                                 /*  ����ļ�ϵͳ״̬            */
        return  (__littleFsStatfs(pfdentry, (struct statfs *)lArg));

   case FIOREADDIR:                                                    /*  ��ȡһ��Ŀ¼��Ϣ            */
       return  (__littleFsReadDir(pfdentry, (DIR *)lArg));

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
    fileop.fo_lstat = __littleFsLStat;
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

    pfs = (PLFS_VOLUME)__SHEAP_ALLOC(sizeof(LFS_VOLUME));
    if (pfs == LW_NULL) {
        _DebugHandle(__ERRORMESSAGE_LEVEL, "LittleFS: system low memory.\r\n");
        _ErrorHandle(ERROR_SYSTEM_LOW_MEMORY);
        return  (PX_ERROR);
    }
    lib_bzero(pfs, sizeof(LFS_VOLUME));                              /*  ��վ���ƿ�                */

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
        // printf("first lfs inner mount failed!\r\n");
        lfs_format(&pfs->lfst, &cfg);
        // if(formaterr<0) printf("first lfs inner formaterr failed!\r\n");
        mounterr = lfs_mount(&pfs->lfst, &cfg);
        // if(mounterr<0) printf("second lfs inner mount failed!\r\n");
    }

    if (iosDevAddEx(&pfs->LFS_devhdrHdr, pcName, _G_iLittleFsDrvNum, DT_DIR)
        != ERROR_NONE) {                                                /*  ��װ�ļ�ϵͳ�豸            */
        API_SemaphoreMDelete(&pfs->LFS_hVolLock);
        __SHEAP_FREE(pfs);
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
