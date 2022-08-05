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
** ��        ��: LittleFs��VFS�Ľӿ��ļ�
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
                                             ����ⲿAPI
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
*                                           LFS��ؽṹ��                                                  *
***********************************************************************************************************/

/* Ϊ��ƥ��SylixOS����lfs_t������һ���װ��������VFS��Ҫ����Ϣ */
typedef struct lfs_volume{
    LW_DEV_HDR          LFS_devhdrHdr;                                /*  lfs�ļ�ϵͳ�豸ͷ        */
    LW_OBJECT_HANDLE    LFS_hVolLock;                                 /*  �������                 */
    LW_LIST_LINE_HEADER LFS_plineFdNodeHeader;                        /*  fd_node ����             */

    BOOL                LFS_bForceDelete;                             /*  �Ƿ�����ǿ��ж�ؾ�        */
    BOOL                LFS_bValid;

    uid_t               LFS_uid;                                      /*  �û� id                  */
    gid_t               LFS_gid;                                      /*  ��   id                  */
    mode_t              LFS_mode;                                     /*  �ļ� mode                */
    time_t              LFS_time;                                     /*  ����ʱ��                  */
    lfs_t               lfst;                                         /*  lfs�ļ�ϵͳ���           */
} LFS_VOLUME;
typedef LFS_VOLUME*     PLFS_VOLUME;

/* Ϊ��ƥ��SylixOS����dir��file���ͷ�װΪnode�ļ��ڵ㣬���������ļ�������Ϣ */
typedef struct lfs_node {
    PLFS_VOLUME         LFSN_plfs;                                      /*       �ļ�ϵͳ               */

    BOOL                LFSN_bChanged;                                  /*       �ļ������Ƿ����          */
    mode_t              LFSN_mode;                                      /*       �ļ� mode              */
    time_t              LFSN_timeCreate;                                /*       ����ʱ��                        */
    time_t              LFSN_timeAccess;                                /*       ������ʱ��                 */
    time_t              LFSN_timeChange;                                /*       ����޸�ʱ��                 */

    size_t              LFSN_stSize;                                    /*  ��ǰ�ļ���С (���ܴ��ڻ���) */
    size_t              LFSN_stVSize;                                   /*      lseek ���������С        */

    uid_t               LFSN_uid;                                       /*         �û� id            */
    gid_t               LFSN_gid;                                       /*         ��   id             */
    
    /* ���������ͣ�����isfile�жϣ�lfsdir��lfsfile����һ��Ϊ�� */
    PCHAR               LFSN_pcLink;                                    /*         ����Ŀ��              */
    bool                isfile;
    lfs_dir_t           lfsdir;
    lfs_file_t          lfsfile;
} LFS_NODE;
typedef LFS_NODE*       PLFS_NODE;

/**********************************************************************************************************
*                                           LFS��Sylixת������                                             *
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
*                                              ���õĺ궨��                                                *
***********************************************************************************************************/

#define __LFS_FILE_LOCK(plfsn)        API_SemaphoreMPend(plfsn->LFSN_plfs->LFS_hVolLock, \
                                      LW_OPTION_WAIT_INFINITE)
#define __LFS_FILE_UNLOCK(plfsn)      API_SemaphoreMPost(plfsn->LFSN_plfs->LFS_hVolLock)
#define __LFS_VOL_LOCK(pfs)           API_SemaphoreMPend(pfs->LFS_hVolLock, \
                                      LW_OPTION_WAIT_INFINITE)
#define __LFS_VOL_UNLOCK(pfs)         API_SemaphoreMPost(pfs->LFS_hVolLock)
#define __STR_IS_ROOT(pcName)         ((pcName[0] == PX_EOS) || (lib_strcmp(PX_STR_ROOT, pcName) == 0))


/**********************************************************************************************************
*                                           �ڲ�ȫ�ֱ���/����                                              *
***********************************************************************************************************/
const static INT BEGIN_OFF_AM29LV160DB   = 256*1024;
static       INT _G_iLittleFsDrvNum      = PX_ERROR;


/**********************************************************************************************************
*                                             �ײ���������                                                 *
***********************************************************************************************************/

/* lfs��ײ�flash�����ݽӿ�
 * @palfs  c      �ļ�ϵͳ���ýṹ��
 * @palfs  block  ����
 * @palfs  off    ����ƫ�Ƶ�ַ
 * @palfs  buffer ���ڴ洢��ȡ��������
 * @palfs  size   Ҫ��ȡ���ֽ���
 * @return                        */
static int lfs_mini2440_read(const struct lfs_config *c, lfs_block_t block, 
                            lfs_off_t off, void *buffer, lfs_size_t size)
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
static int lfs_mini2440_prog(const struct lfs_config *c, lfs_block_t block, 
                            lfs_off_t off, const void *buffer, lfs_size_t size)
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

/**********************************************************************************************************
*                                      �ļ�ϵͳĬ�ϳ�ʼ�����ã���Ҫ������                                    *
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
** ��������: __little_stat
** ��������: lfs ����ļ� stat
** �䡡��  : plfsn           �ļ��ڵ�
**           plfs           �ļ�ϵͳ
**           pstat          ��õ� stat
** �䡡��  : �������
** ȫ�ֱ���:
** ����ģ��:
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
                                     mode_t      mode,
                                     PCHAR       pcLink)
{
    int err = 0;

    PLFS_NODE plfsn = (PLFS_NODE)__SHEAP_ALLOC(sizeof(LFS_NODE)); /*    �����ڴ棬�����ڵ�       */
    // printf("__lfs_maken(): PLFS_NODE plfsn = (PLFS_NODE)__SHEAP_ALLOC(sizeof(LFS_NODE));\r\n");
    if (plfsn == LW_NULL){
        _ErrorHandle(ENOMEM);
        return  (NULL);
    }
    lib_bzero(plfsn,sizeof(LFS_NODE));                            /*       �ڵ����          */

    if (S_ISLNK(mode)){                                           /*     ��������(����)      */
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
        err = lfs_mkdir(&plfs->lfst, pcName);                     /*     ��������(Ŀ¼)      */
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
    } else {                                                      /*     ��������(�ļ�)      */
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

/* �����Ĵ��ļ���Ŀ¼�����ڵ㲻���ڲ��ᴴ���ڵ� */
static inline PLFS_NODE __lfs_open (PLFS_VOLUME pfs,
                                    PCHAR       pcName,
                                    INT         iFlags,
                                    INT         iMode,
                                    BOOL*       broot)
{
    int err = 0;
    CHAR pcLink[256];

    /* �����ж��Ƿ����ļ�ϵͳ��Ŀ¼ */
    *broot = FALSE;
    if (*pcName == PX_ROOT) {                                     /*       ���Ը�����       */
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

    PLFS_NODE plfsn = (PLFS_NODE)__SHEAP_ALLOC(sizeof(LFS_NODE));         /*  �����ڴ棬�����ڵ�    */
    // printf("__lfs_open(): PLFS_NODE plfsn = (PLFS_NODE)__SHEAP_ALLOC(sizeof(LFS_NODE));\r\n");
    if (plfsn == LW_NULL){
        _ErrorHandle(ENOMEM);
        return  (NULL);
    }
    lib_bzero(plfsn,sizeof(LFS_NODE));                                    /*     �ڵ����             */
    
    /* ���ﲻ��iMode�ж��ļ�����Ŀ¼������Ϊ��ʱ��Ϣδ��ȡ��iModeδ֪��*/
    err = lfs_file_open(&pfs->lfst, &plfsn->lfsfile,             //TODO
                                pcName, genLfsFlag(iMode, iFlags));
    if(err >= 0){
        plfsn->isfile = true;
        int getattr = lfs_getattr(&pfs->lfst, pcName, LFS_TYPE_SLINK,
                                  (PCHAR)pcLink, 256);
        if(getattr < 0){                                                 /*    �������ļ�����      */
            __lfs_init_plfsn(plfsn, pfs, iMode|S_IFREG);
            plfsn->LFSN_pcLink = LW_NULL;
            printf("lfs_file_open() success, type is file!\r\n");
        }else{                                                           /*    �����ļ�����         */
            __lfs_init_plfsn(plfsn, pfs, iMode|S_IFLNK);
            plfsn->LFSN_pcLink = (PCHAR)__SHEAP_ALLOC(getattr+1);
            // printf("%%% __lfs_open(): plfsn->LFSN_pcLink = (PCHAR)__SHEAP_ALLOC(getattr+1);\r\n");
            // printf("size: %d , p: %p \r\n",getattr+1, plfsn->LFSN_pcLink);
            lib_strncpy(plfsn->LFSN_pcLink, (PCHAR)pcLink, getattr+1);
            printf("lfs_file_open() success, type is link!\r\n");
        } 
    }else{                                                               /*    Ŀ¼�ļ�����         */
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

/* ɾ��һ���ļ����ļ��нڵ� */
static inline INT  __lfs_unlink (PLFS_NODE  plfsn)
{
    PLFS_VOLUME     plfs = plfsn->LFSN_plfs;
    
    if (plfsn!=NULL && plfsn!=PX_ERROR && S_ISDIR(plfsn->LFSN_mode)) {          /* �ж�Ŀ¼��Ϊ�� */                               /*    �ļ�����Ҫɾ��������Ϊ��    */
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
