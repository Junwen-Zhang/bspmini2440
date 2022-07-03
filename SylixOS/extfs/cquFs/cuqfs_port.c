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
** ��   ��   ��: cqufs_port.h
**
** ��   ��   ��: cqu Group
**
** �ļ���������: 2022 �� 06 �� 04 ��
**
** ��        ��: cqufs���Ͻӿ��ļ�
*********************************************************************************************************/
#define  __SYLIXOS_STDIO
#define  __SYLIXOS_KERNEL //�������������ʹ���Ѷ�����ں˺����ͽṹ
#include "cqufs.h"
#include "cqufs_port.h"
#include "../../driver/mtd/nor/nor.h"
#include "SylixOS.h"

#ifndef LITTLEFS_DISABLE



/* Ϊ��ƥ��SylixOS����SuperBlock������һ���װ���������ļ�������Ϣ */
typedef struct cqufs_volume{
    LW_DEV_HDR          CQUFS_devhdrHdr;                                /*  cqufs �ļ�ϵͳ�豸ͷ        */
    LW_OBJECT_HANDLE    CQUFS_hVolLock;                                 /*  �������                    */
    LW_LIST_LINE_HEADER CQUFS_plineFdNodeHeader;                        /*  fd_node ����                */
    LW_LIST_LINE_HEADER CQUFS_plineSon;                                 /*  ��������                    */

    BOOL                CQUFS_bForceDelete;                             /*  �Ƿ�����ǿ��ж�ؾ�          */
    BOOL                CQUFS_bValid;

    uid_t               CQUFS_uid;                                      /*  �û� id                     */
    gid_t               CQUFS_gid;                                      /*  ��   id                     */
    mode_t              CQUFS_mode; //new xmy
    time_t              CQUFS_time;                                     /*  ����ʱ��                    */

    //new xmy
    ULONG               CQUFS_ulCurBlk;
    ULONG               CQUFS_ulMaxBlk;

    cqufs_t* cqufst;
    // struct cqufs_config* mycfg;
    //const struct cqufs_config cfg;
} CQUFS_VOLUME;
typedef CQUFS_VOLUME*     PCQUFS_VOLUME;

/* Ϊ��ƥ��SylixOS����dir��file���ͷ�װΪnode�ļ��ڵ㣬���������ļ�������Ϣ */
typedef struct cqufs_node {
    PCQUFS_VOLUME         CQUFSN_pcqufs;                                    /*  �ļ�ϵͳ                    */

    BOOL                CQUFSN_bChanged;                                  /*  �ļ������Ƿ����            */
    mode_t              CQUFSN_mode;                                      /*  �ļ� mode                   */
    time_t              CQUFSN_timeCreate;                                /*  ����ʱ��                    */
    time_t              CQUFSN_timeAccess;                                /*  ������ʱ��                */
    time_t              CQUFSN_timeChange;                                /*  ����޸�ʱ��                */

    size_t              CQUFSN_stSize;                                    /*  ��ǰ�ļ���С (���ܴ��ڻ���) */
    size_t              CQUFSN_stVSize;                                   /*  lseek ���������С          */

    uid_t               CQUFSN_uid;                                       /*  �û� id                     */
    gid_t               CQUFSN_gid;                                       /*  ��   id                     */
    PCHAR               CQUFSN_pcName;                                    /*  �ļ�����                    */
    PCHAR               CQUFSN_pcLink;                                    /*  ����Ŀ��                    */

    /* ���������ͣ�����isfile�жϣ�����һ��ָ��Ϊ�� */
    bool isfile;
    cqufs_dir_t* cqufsdir;
    cqufs_file_t* cqufsfile;
} CQUFS_NODE;
typedef CQUFS_NODE*       PCQUFS_NODE;

#define __CQUFS_FILE_LOCK(pcqufsn)        API_SemaphoreMPend(pcqufsn->CQUFSN_pcqufs->CQUFS_hVolLock, \
                                      LW_OPTION_WAIT_INFINITE)
#define __CQUFS_FILE_UNLOCK(pcqufsn)      API_SemaphoreMPost(pcqufsn->CQUFSN_pcqufs->CQUFS_hVolLock)

#define __CQUFS_VOL_LOCK(pfs)           API_SemaphoreMPend(pfs->CQUFS_hVolLock, \
                                      LW_OPTION_WAIT_INFINITE)
#define __CQUFS_VOL_UNLOCK(pfs)         API_SemaphoreMPost(pfs->CQUFS_hVolLock)

#define __STR_IS_ROOT(pcName)         ((pcName[0] == PX_EOS) || (lib_strcmp(PX_STR_ROOT, pcName) == 0))


/***********************************************************************************************************
*                                         ����һЩ�ڲ�����                                                 *
***********************************************************************************************************/
const static INT READ_SIZE_AM29LV160DB        = 16;
const static INT PROG_SIZE_AM29LV160DB        = 16;
const static INT BLOCK_SIZE_AM29LV160DB       = 64 * 1024;
const static INT BLOCK_COUNT_AM29LV160DB      = 32;
const static INT CACHE_SIZE_AM29LV160DB       = 1024;
const static INT LOOKAHEAD_SIZE_AM29LV160DB   = 16;
const static INT BLOCK_CYCLES_AM29LV160DB     = 500;

static INT _G_iLittleFsDrvNum           = PX_ERROR;

/***********************************************************************************************************
*                                         һЩ�ڲ�����                                                     *
***********************************************************************************************************/

/* ���������д��������NorFlash�����Ľӿ�,������������ */

/**
 * cqufs��ײ�flash�����ݽӿ�
 * @pacqufs  c
 * @pacqufs  block  ����
 * @pacqufs  off    ����ƫ�Ƶ�ַ
 * @pacqufs  buffer ���ڴ洢��ȡ��������
 * @pacqufs  size   Ҫ��ȡ���ֽ���
 * @return
 */
static int cqufs_mini2440_read(const struct cqufs_config *c, cqufs_block_t block, cqufs_off_t off, void *buffer, cqufs_size_t size)
{
    //xmy
    // write_nor(c->block_size * block + off, buffer, size, WRITE_KEEP);
    // read_nor(off,buffer,size);
    printf("cqufs_mini2440_read--------------\n");
    int a = read_nor(c->block_size * block + off, buffer, size);
    printf("%d---------------\n",a);
    //printf("%s -------------------------------\n",buffer);
    return CQUFS_ERR_OK;
}

/**
 * cqufs��ײ�flashд���ݽӿ�
 * @pacqufs  c
 * @pacqufs  block  ����
 * @pacqufs  off    ����ƫ�Ƶ�ַ
 * @pacqufs  buffer ��д�������
 * @pacqufs  size   ��д�����ݵĴ�С
 * @return
 */
static int cqufs_mini2440_prog(const struct cqufs_config *c, cqufs_block_t block, cqufs_off_t off, const void *buffer, cqufs_size_t size)
{
    // read_nor(c->block_size * block + off, buffer, size);
    printf("cqufs_mini2440_write--------------\n");
    write_nor(c->block_size * block + off, buffer, size, WRITE_KEEP);
    return CQUFS_ERR_OK;
}

/**
 * cqufs��ײ�flash�����ӿ�
 * @pacqufs  c
 * @pacqufs  block ����
 * @return
 */
static int cqufs_mini2440_erase(const struct cqufs_config *c, cqufs_block_t block)
{
    printf("cqufs_mini2440_erase--------------\n");
    erase_nor(c->block_size * block, ERASE_SECTOR);
    return CQUFS_ERR_OK;
}

static int cqufs_mini2440_sync(const struct cqufs_config *c)
{
    printf("cqufs_mini2440_sync--------------\n");
    return CQUFS_ERR_OK;
}

// static inline void littleConfigInitialize(struct cqufs_config* cfg){
//     printf("littleConfigInitialize 1-----------------\n");
//     // ��̬�ڴ�ʹ�÷�ʽ�����趨���ĸ�����
//     __align(4) static uint8_t read_buffer[16];
//     __align(4) static uint8_t prog_buffer[16];
//     __align(4) static uint8_t lookahead_buffer[16];

//     printf("littleConfigInitialize 2-----------------\n");
//     // block device operations
//     //cfg->read = NULL;
//     printf("littleConfigInitialize 2 read -----------------------\n");
//     cfg->read  = cqufs_mini2440_read;
//     printf("littleConfigInitialize 2 read finish-----------------\n");
//     cfg->prog  = cqufs_mini2440_prog;
//     cfg->erase = cqufs_mini2440_erase;
//     cfg->sync  = cqufs_mini2440_sync;

//     printf("littleConfigInitialize 3-----------------\n");
//     // block device configuration
    // cfg->read_size = READ_SIZE_AM29LV160DB;
    // cfg->prog_size = PROG_SIZE_AM29LV160DB;
    // cfg->block_size = BLOCK_SIZE_AM29LV160DB;
    // cfg->block_count = BLOCK_COUNT_AM29LV160DB;
    // cfg->cache_size = CACHE_SIZE_AM29LV160DB;
    // cfg->lookahead_size = LOOKAHEAD_SIZE_AM29LV160DB;
    // cfg->block_cycles = BLOCK_CYCLES_AM29LV160DB;
    
//     printf("littleConfigInitialize 4-----------------\n");
//     // ʹ�þ�̬�ڴ���������⼸������
//     cfg->read_buffer = read_buffer;
//     cfg->prog_buffer = prog_buffer;
//     cfg->lookahead_buffer = lookahead_buffer;
// }

//xmy
// cqufs���
cqufs_t cqufs_test;
// cqufs_file_t cqufs_file_w25qxx;
__align(4) static uint8_t read_buffer[16];
__align(4) static uint8_t prog_buffer[16];
__align(4) static uint8_t lookahead_buffer[16];
const struct cqufs_config cfg =
{
	// block device operations
	.read  = cqufs_mini2440_read,
	.prog  = cqufs_mini2440_prog,
	.erase = cqufs_mini2440_erase,
	.sync  = cqufs_mini2440_sync,

	// block device configuration
	.read_size = 16,
	.prog_size = 16,
	.block_size = 64 * 1024,
	.block_count = 32,
	.cache_size = 1024,
	.lookahead_size = 16,
	.block_cycles = 500,

	//
	// ʹ�þ�̬�ڴ���������⼸������
	//
	.read_buffer = read_buffer,
	.prog_buffer = prog_buffer,
	.lookahead_buffer = lookahead_buffer,
};


/*********************************************************************************************************
** ��������: __little_stat
** ��������: cqufs ����ļ� stat
** �䡡��  : pcqufsn            �ļ��ڵ�
**           pcqufs           �ļ�ϵͳ
**           pstat            ��õ� stat
** �䡡��  : �������
** ȫ�ֱ���:
** ����ģ��:
*********************************************************************************************************/
static inline void __cqufs_stat (PCQUFS_NODE  pcqufsn, PCQUFS_VOLUME  pcqufs, struct stat  *pstat)
{
    if (pcqufsn) {
        pstat->st_dev     = LW_DEV_MAKE_STDEV(&pcqufs->CQUFS_devhdrHdr);
        pstat->st_ino     = (ino_t)pcqufsn;
        pstat->st_mode    = pcqufsn->CQUFSN_mode;
        pstat->st_nlink   = 1;
        pstat->st_uid     = pcqufsn->CQUFSN_uid;
        pstat->st_gid     = pcqufsn->CQUFSN_gid;
        pstat->st_rdev    = 1;
        pstat->st_size    = (off_t)pcqufsn->CQUFSN_stSize;
        pstat->st_atime   = pcqufsn->CQUFSN_timeAccess;
        pstat->st_mtime   = pcqufsn->CQUFSN_timeChange;
        pstat->st_ctime   = pcqufsn->CQUFSN_timeCreate;
    
    } else {
        pstat->st_dev     = LW_DEV_MAKE_STDEV(&pcqufs->CQUFS_devhdrHdr);
        pstat->st_ino     = (ino_t)0;
        pstat->st_nlink   = 1;
        pstat->st_uid     = pcqufs->CQUFS_uid;
        pstat->st_gid     = pcqufs->CQUFS_gid;
        pstat->st_rdev    = 1;
        pstat->st_size    = 0;
        pstat->st_atime   = pcqufs->CQUFS_time;
        pstat->st_mtime   = pcqufs->CQUFS_time;
        pstat->st_ctime   = pcqufs->CQUFS_time;
        pstat->st_blocks  = 0;
    }  
    pstat->st_resv1 = LW_NULL;
    pstat->st_resv2 = LW_NULL;
    pstat->st_resv3 = LW_NULL;
}

/*********************************************************************************************************
** ��������: __little_statfs
** ��������: cqufs ����ļ� stat
** �䡡��  : pfs           �ļ�ϵͳ
**           pstatfs          ��õ� statfs
** �䡡��  : �������
** ȫ�ֱ���:
** ����ģ��:
*********************************************************************************************************/
static inline void  __cqufs_statfs (PCQUFS_VOLUME  pfs, struct statfs  *pstatfs)
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
** �䡡��  : pfs              �ڴ���HoitFs�ļ�ϵͳ��super block
**           pcName           �ļ���
**           iFlags           ��ʽ
**           iMode            mode_t
** �䡡��  : < 0 ����
** ȫ�ֱ���:
** ����ģ��:
*********************************************************************************************************/
static LONG __littleFsOpen(PCQUFS_VOLUME     pfs,
    PCHAR           pcName,
    INT             iFlags,
    INT             iMode)
{
    PLW_FD_NODE         pfdnode;
    cqufs_file_t* pcqufsfile;
    cqufs_dir_t* pcqufsdir;
    PCQUFS_NODE pcqufsn;
    struct stat statGet;
    BOOL        bIsNew;
//    BOOL        bCreate = LW_FALSE;

    if (pcName == LW_NULL) {
        _ErrorHandle(EFAULT);                                           /*  Bad address                 */
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
            S_ISLNK(iMode)) {
            _ErrorHandle(ERROR_IO_DISK_NOT_PRESENT);                    /*  ��֧��������Щ��ʽ          */
            return  (PX_ERROR);
        }
    }

    if (__CQUFS_VOL_LOCK(pfs) != ERROR_NONE) {
        _ErrorHandle(ENXIO);                                            /*  �豸����                    */
        return  (PX_ERROR);
    }

    /************************************ TODO ************************************/
    
    
    if(S_ISDIR(iMode)){
        cqufs_dir_open(pfs->cqufst,pcqufsdir,pcName);
        pcqufsn->isfile=false;
        pcqufsn->cqufsdir=pcqufsdir;
    }
    else{
        if(S_ISREG(iMode))cqufs_file_open(pfs->cqufst,pcqufsfile,pcName,iFlags);
        pcqufsn->isfile=true;
        pcqufsn->cqufsfile=pcqufsfile;
    }

    if (pcqufsfile||pcqufsdir) {
        if (!S_ISLNK(pcqufsn->CQUFSN_mode)) {
            if ((iFlags & O_CREAT) && (iFlags & O_EXCL)) {              /*  ���������ļ�                */
                __CQUFS_VOL_UNLOCK(pfs);
                _ErrorHandle(EEXIST);                                   /*  �Ѿ������ļ�                */
                return  (PX_ERROR);            
            } else if ((iFlags & O_DIRECTORY) && !S_ISDIR(pcqufsn->CQUFSN_mode)) {
                __CQUFS_VOL_UNLOCK(pfs);
                _ErrorHandle(ENOTDIR);
                return  (PX_ERROR);
            } 
        }
    } 

    __cqufs_stat(pcqufsn, pfs, &statGet);
    pfdnode = API_IosFdNodeAdd(&pfs->CQUFS_plineFdNodeHeader,
                               statGet.st_dev,
                               (ino64_t)statGet.st_ino,
                               iFlags,
                               iMode,
                               statGet.st_uid,
                               statGet.st_gid,
                               statGet.st_size,
                               (PVOID)pcqufsn,
                               &bIsNew);    

    pfdnode->FDNODE_pvFsExtern = (PVOID)pfs;                            /*  ��¼�ļ�ϵͳ��Ϣ            */

    LW_DEV_INC_USE_COUNT(&pfs->CQUFS_devhdrHdr);                          /*  ���¼�����                  */
    __CQUFS_VOL_UNLOCK(pfs);

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
static INT  __littleFsRemove (PCQUFS_VOLUME   pfs,
                           PCHAR         pcName)
{
//    PLW_FD_NODE         pfdnode;
    cqufs_file_t* pcqufsfile;
    cqufs_dir_t* pcqufsdir;
    PCQUFS_NODE pcqufsn;

    // BOOL       bRoot;
    // PCHAR      pcTail;
    // INT        iError;

    if (pcName == LW_NULL) {
        _ErrorHandle(ERROR_IO_NO_DEVICE_NAME_IN_PATH);
        return  (PX_ERROR);
    }
        
    if (__CQUFS_VOL_LOCK(pfs) != ERROR_NONE) {
        _ErrorHandle(ENXIO);                                            /*  �豸����                    */
        return  (PX_ERROR);
    }
    
    struct cqufs_info* cqufsinfo;
    int error=cqufs_stat(pfs->cqufst,pcName,cqufsinfo);
    if(!error){
        if(cqufsinfo->type==CQUFS_TYPE_DIR){
            cqufs_dir_open(pfs->cqufst,pcqufsdir,pcName);
            pcqufsn->isfile=false;
            pcqufsn->cqufsdir=pcqufsdir;
        }
        else{
            cqufs_file_open(pfs->cqufst,pcqufsfile,pcName,CQUFS_O_RDWR);
            pcqufsn->isfile=true;
            pcqufsn->cqufsfile=pcqufsfile;
        }
    }else{
        __CQUFS_VOL_UNLOCK(pfs);
        _ErrorHandle(ENOENT);
        return  (PX_ERROR);
    }
    
    if (pcqufsfile||pcqufsdir) {
        cqufs_remove(pfs->cqufst,pcName);
        __CQUFS_VOL_UNLOCK(pfs);
        return  (ERROR_NONE);
            
    } else if (!pcName) {                                                 /*  ɾ�� cqufs �ļ�ϵͳ         */
        if (pfs->CQUFS_bValid == LW_FALSE) {
            __CQUFS_VOL_UNLOCK(pfs);
            return  (ERROR_NONE);                                       /*  ���ڱ���������ж��          */
        }
        
__re_umount_vol:
    if (LW_DEV_GET_USE_COUNT((LW_DEV_HDR *)pfs)) {
        if (!pfs->CQUFS_bForceDelete) {
            __CQUFS_VOL_UNLOCK(pfs);
            _ErrorHandle(EBUSY);
            return  (PX_ERROR);
        }
        
        pfs->CQUFS_bValid = LW_FALSE;
        
        __CQUFS_VOL_UNLOCK(pfs);
        
        _DebugHandle(__ERRORMESSAGE_LEVEL, "LittleFS: disk have open file.\r\n");
        iosDevFileAbnormal(&pfs->CQUFS_devhdrHdr);               /*  ����������ļ���Ϊ�쳣ģʽ  */
        
        __CQUFS_VOL_LOCK(pfs);
        goto    __re_umount_vol;
    
    } else {
        pfs->CQUFS_bValid = LW_FALSE;
    }
        
        iosDevDelete((LW_DEV_HDR *)pfs);                             /*  IO ϵͳ�Ƴ��豸             */
        API_SemaphoreMDelete(&pfs->CQUFS_hVolLock);
        
        cqufs_unmount(pfs->cqufst);                                          /*  �ͷ������ļ�����            */
        __SHEAP_FREE(pfs);
        
        _DebugHandle(__LOGMESSAGE_LEVEL, "LittleFS: Lfs unmount ok.\r\n");
        
        return  (ERROR_NONE);
        
    } else {
        __CQUFS_VOL_UNLOCK(pfs);
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
    PCQUFS_NODE     pcqufsn   = (PCQUFS_NODE)pfdnode->FDNODE_pvFile;
    PCQUFS_VOLUME   pfs  = (PCQUFS_VOLUME)pfdnode->FDNODE_pvFsExtern;
    BOOL          bRemove = LW_FALSE;
    
    if (__CQUFS_VOL_LOCK(pfs) != ERROR_NONE) {
        _ErrorHandle(ENXIO);                                            /*  �豸����                    */
        return  (PX_ERROR);
    }
    
    if (API_IosFdNodeDec(&pfs->CQUFS_plineFdNodeHeader, 
                         pfdnode, &bRemove) == 0) {
        if (pcqufsn->cqufsdir) {
            cqufs_dir_close(pfs->cqufst, pcqufsn->cqufsdir);
        }else{
            cqufs_file_close(pfs->cqufst, pcqufsn->cqufsfile);
        }
    }
    
    LW_DEV_DEC_USE_COUNT(&pfs->CQUFS_devhdrHdr);
        
    __CQUFS_VOL_UNLOCK(pfs);

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
    PCQUFS_NODE     pcqufsn      = (PCQUFS_NODE)pfdnode->FDNODE_pvFile;
    ssize_t       sstReadNum = PX_ERROR;
    
    if (!pcBuffer) {
        _ErrorHandle(EINVAL);
        return  (PX_ERROR);
    }
    
    if (pcqufsn == LW_NULL) {
        _ErrorHandle(EISDIR);
        return  (PX_ERROR);
    }
    
    if (__CQUFS_FILE_LOCK(pcqufsn) != ERROR_NONE) {
        _ErrorHandle(ENXIO);
        return  (PX_ERROR);
    }
    
    if (S_ISDIR(pcqufsn->CQUFSN_mode)) {
        __CQUFS_FILE_UNLOCK(pcqufsn);
        _ErrorHandle(EISDIR);
        return  (PX_ERROR);
    }
    
    if (stMaxBytes) {
        if(pcqufsn->cqufsdir){
            _DebugHandle(__LOGMESSAGE_LEVEL, "LittleFS: you can not resd a directory.\r\n");
        }else{
            sstReadNum = cqufs_file_read(pcqufsn->CQUFSN_pcqufs, pcqufsn->cqufsfile, pcBuffer, stMaxBytes);
            if (sstReadNum > 0) {
                pfdentry->FDENTRY_oftPtr += (off_t)sstReadNum;              /*  �����ļ�ָ��                */
            }  
        }        
    } else {
        sstReadNum = 0;
    }
    
    __CQUFS_FILE_UNLOCK(pcqufsn);
    
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
    PCQUFS_NODE     pcqufsn      = (PCQUFS_NODE)pfdnode->FDNODE_pvFile;
    ssize_t       sstReadNum = PX_ERROR;
    
    if (!pcBuffer || (oftPos < 0)) {
        _ErrorHandle(EINVAL);
        return  (PX_ERROR);
    }
    
    if (pcqufsn == LW_NULL) {
        _ErrorHandle(EISDIR);
        return  (PX_ERROR);
    }
    
    if (__CQUFS_FILE_LOCK(pcqufsn) != ERROR_NONE) {
        _ErrorHandle(ENXIO);
        return  (PX_ERROR);
    }
    
    if (S_ISDIR(pcqufsn->CQUFSN_mode)) {
        __CQUFS_FILE_UNLOCK(pcqufsn);
        _ErrorHandle(EISDIR);
        return  (PX_ERROR);
    }
    
    if (stMaxBytes) {
        if(pcqufsn->cqufsdir){
            _DebugHandle(__LOGMESSAGE_LEVEL, "LittleFS: you can not resd a directory.\r\n");
        }else{
            cqufs_file_seek(pcqufsn->CQUFSN_pcqufs, pcqufsn->cqufsfile,oftPos,CQUFS_SEEK_SET);
            sstReadNum = cqufs_file_read(pcqufsn->CQUFSN_pcqufs, pcqufsn->cqufsfile, pcBuffer, stMaxBytes);
            if (sstReadNum > 0) {
                pfdentry->FDENTRY_oftPtr += (off_t)sstReadNum;              /*  �����ļ�ָ��                */
            }  
        }
         
    } else {
        sstReadNum = 0;
    }
    
    __CQUFS_FILE_UNLOCK(pcqufsn);
    
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
    PCQUFS_NODE     pcqufsn       = (PCQUFS_NODE)pfdnode->FDNODE_pvFile;
    ssize_t       sstWriteNum = PX_ERROR;
    
    if (!pcBuffer) {
        _ErrorHandle(EINVAL);
        return  (PX_ERROR);
    }
    
    if (pcqufsn == LW_NULL) {
        _ErrorHandle(EISDIR);
        return  (PX_ERROR);
    }
    
    if (__CQUFS_FILE_LOCK(pcqufsn) != ERROR_NONE) {
        _ErrorHandle(ENXIO);
        return  (PX_ERROR);
    }
    
    if (S_ISDIR(pcqufsn->CQUFSN_mode)) {
        __CQUFS_FILE_UNLOCK(pcqufsn);
        _ErrorHandle(EISDIR);
        return  (PX_ERROR);
    }
    
    if (pfdentry->FDENTRY_iFlag & O_APPEND) {                           /*  ׷��ģʽ                    */
        pfdentry->FDENTRY_oftPtr = pfdnode->FDNODE_oftSize;             /*  �ƶ���дָ�뵽ĩβ          */
    }

    if (stNBytes) {
        if(pcqufsn->cqufsdir){
            _DebugHandle(__LOGMESSAGE_LEVEL, "LittleFS: you can not write a directory.\r\n");
        }else{
            sstWriteNum = cqufs_file_write(pcqufsn->CQUFSN_pcqufs, pcqufsn->cqufsfile, pcBuffer, stNBytes);
        }
        if (sstWriteNum > 0) {
                pfdentry->FDENTRY_oftPtr += (off_t)sstWriteNum;             /*  �����ļ�ָ��                */
                pfdnode->FDNODE_oftSize   = (off_t)pcqufsn->CQUFSN_stSize;
        }   
    } else {
        sstWriteNum = 0;
    }
    
    __CQUFS_FILE_UNLOCK(pcqufsn);
    
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
    PCQUFS_NODE     pcqufsn       = (PCQUFS_NODE)pfdnode->FDNODE_pvFile;
    ssize_t       sstWriteNum = PX_ERROR;
    
    if (!pcBuffer || (oftPos < 0)) {
        _ErrorHandle(EINVAL);
        return  (PX_ERROR);
    }
    
    if (pcqufsn == LW_NULL) {
        _ErrorHandle(EISDIR);
        return  (PX_ERROR);
    }
    
    if (__CQUFS_FILE_LOCK(pcqufsn) != ERROR_NONE) {
        _ErrorHandle(ENXIO);
        return  (PX_ERROR);
    }
    
    if (S_ISDIR(pcqufsn->CQUFSN_mode)) {
        __CQUFS_FILE_UNLOCK(pcqufsn);
        _ErrorHandle(EISDIR);
        return  (PX_ERROR);
    }
    
    if (stNBytes) {
        if(pcqufsn->cqufsdir){
            _DebugHandle(__LOGMESSAGE_LEVEL, "LittleFS: you can not write a directory.\r\n");
        }else{
            cqufs_file_seek(pcqufsn->CQUFSN_pcqufs, pcqufsn->cqufsfile,oftPos,CQUFS_SEEK_SET);
            sstWriteNum = cqufs_file_write(pcqufsn->CQUFSN_pcqufs, pcqufsn->cqufsfile, pcBuffer, stNBytes);
        }
        if (sstWriteNum > 0) {
                pfdentry->FDENTRY_oftPtr += (off_t)sstWriteNum;             /*  �����ļ�ָ��                */
                pfdnode->FDNODE_oftSize   = (off_t)pcqufsn->CQUFSN_stSize;
        }   
    } else {
        sstWriteNum = 0;
    }
    
    __CQUFS_FILE_UNLOCK(pcqufsn);
    
    return  (sstWriteNum);
}

/*********************************************************************************************************
** ��������: __littleFsNRead
** ��������: cqufsFs nread ����
** �䡡��  : pfdentry         �ļ����ƿ�
**           piNRead          ʣ��������
** �䡡��  : �������
** ȫ�ֱ���:
** ����ģ��:
*********************************************************************************************************/
static INT  __littleFsNRead (PLW_FD_ENTRY  pfdentry, INT  *piNRead)
{
    PLW_FD_NODE   pfdnode = (PLW_FD_NODE)pfdentry->FDENTRY_pfdnode;
    PCQUFS_NODE     pcqufsn   = (PCQUFS_NODE)pfdnode->FDNODE_pvFile;
    
    if (piNRead == LW_NULL) {
        _ErrorHandle(EINVAL);
        return  (PX_ERROR);
    }
    
    if (pcqufsn == LW_NULL) {
        _ErrorHandle(EISDIR);
        return  (PX_ERROR);
    }
    
    if (__CQUFS_FILE_LOCK(pcqufsn) != ERROR_NONE) {
        _ErrorHandle(ENXIO);
        return  (PX_ERROR);
    }
    
    if (S_ISDIR(pcqufsn->CQUFSN_mode)) {
        __CQUFS_FILE_UNLOCK(pcqufsn);
        _ErrorHandle(EISDIR);
        return  (PX_ERROR);
    }
    
    *piNRead = (INT)(pcqufsn->CQUFSN_stSize - (size_t)pfdentry->FDENTRY_oftPtr);
    
    __CQUFS_FILE_UNLOCK(pcqufsn);
    
    return  (ERROR_NONE);
}

/*********************************************************************************************************
** ��������: __littleFsNRead64
** ��������: cqufsFs nread ����
** �䡡��  : pfdentry         �ļ����ƿ�
**           poftNRead        ʣ��������
** �䡡��  : �������
** ȫ�ֱ���:
** ����ģ��:
*********************************************************************************************************/
static INT  __littleFsNRead64 (PLW_FD_ENTRY  pfdentry, off_t  *poftNRead)
{
    PLW_FD_NODE   pfdnode = (PLW_FD_NODE)pfdentry->FDENTRY_pfdnode;
    PCQUFS_NODE     pcqufsn   = (PCQUFS_NODE)pfdnode->FDNODE_pvFile;
    
    if (pcqufsn == LW_NULL) {
        _ErrorHandle(EISDIR);
        return  (PX_ERROR);
    }
    
    if (__CQUFS_FILE_LOCK(pcqufsn) != ERROR_NONE) {
        _ErrorHandle(ENXIO);
        return  (PX_ERROR);
    }
    
    if (S_ISDIR(pcqufsn->CQUFSN_mode)) {
        __CQUFS_FILE_UNLOCK(pcqufsn);
        _ErrorHandle(EISDIR);
        return  (PX_ERROR);
    }
    
    *poftNRead = (off_t)(pcqufsn->CQUFSN_stSize - (size_t)pfdentry->FDENTRY_oftPtr);
    
    __CQUFS_FILE_UNLOCK(pcqufsn);
    
    return  (ERROR_NONE);
}

/*********************************************************************************************************
** ��������: __littleFsSeek
** ��������: cqufsFs seek ����
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
    PCQUFS_NODE     pcqufsn   = (PCQUFS_NODE)pfdnode->FDNODE_pvFile;
    
    if (pcqufsn == LW_NULL) {
        _ErrorHandle(EISDIR);
        return  (PX_ERROR);
    }
    
    if (oftOffset > (size_t)~0) {
        _ErrorHandle(EOVERFLOW);
        return  (PX_ERROR);
    }
    
    if (__CQUFS_FILE_LOCK(pcqufsn) != ERROR_NONE) {
        _ErrorHandle(ENXIO);
        return  (PX_ERROR);
    }
    
    if (S_ISDIR(pcqufsn->CQUFSN_mode)) {
        __CQUFS_FILE_UNLOCK(pcqufsn);
        _ErrorHandle(EISDIR);
        return  (PX_ERROR);
    }
    
    cqufs_file_seek(pcqufsn->CQUFSN_pcqufs, pcqufsn->cqufsfile,oftOffset,CQUFS_SEEK_SET);
    pfdentry->FDENTRY_oftPtr = oftOffset;
    if (pcqufsn->CQUFSN_stVSize < (size_t)oftOffset) {
        pcqufsn->CQUFSN_stVSize = (size_t)oftOffset;
    }
    
    __CQUFS_FILE_UNLOCK(pcqufsn);
    
    return  (ERROR_NONE);
}
/*********************************************************************************************************
** ��������: __littleFsWhere
** ��������: cqufsFs ����ļ���ǰ��дָ��λ�� (ʹ�ò�����Ϊ����ֵ, �� FIOWHERE ��Ҫ�����в�ͬ)
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
** ��������: cqufsFs stat ����
** �䡡��  : pfdentry         �ļ����ƿ�
**           pstat            �ļ�״̬
** �䡡��  : < 0 ��ʾ����
** ȫ�ֱ���:
** ����ģ��:
*********************************************************************************************************/
static INT  __littleFsStat (PLW_FD_ENTRY  pfdentry, struct stat *pstat)
{
    PLW_FD_NODE   pfdnode = (PLW_FD_NODE)pfdentry->FDENTRY_pfdnode;
    PCQUFS_NODE     pcqufsn   = (PCQUFS_NODE)pfdnode->FDNODE_pvFile;
    PCQUFS_VOLUME   pfs  = (PCQUFS_VOLUME)pfdnode->FDNODE_pvFsExtern;
    
    if (!pstat) {
        _ErrorHandle(EINVAL);
        return  (PX_ERROR);
    }
    
    if (__CQUFS_VOL_LOCK(pfs) != ERROR_NONE) {
        _ErrorHandle(ENXIO);
        return  (PX_ERROR);
    }
    
    __cqufs_stat(pcqufsn, pfs, pstat);
    
    __CQUFS_VOL_UNLOCK(pfs);
    
    return  (ERROR_NONE);
}

/*********************************************************************************************************
** ��������: __littleFsStatfs
** ��������: cqufsFs statfs ����
** �䡡��  : pfdentry         �ļ����ƿ�
**           pstatfs          �ļ�ϵͳ״̬
** �䡡��  : < 0 ��ʾ����
** ȫ�ֱ���:
** ����ģ��:
*********************************************************************************************************/
static INT  __littleFsStatfs (PLW_FD_ENTRY  pfdentry, struct statfs *pstatfs)
{
    PLW_FD_NODE   pfdnode = (PLW_FD_NODE)pfdentry->FDENTRY_pfdnode;
    PCQUFS_VOLUME   pfs  = (PCQUFS_VOLUME)pfdnode->FDNODE_pvFsExtern;
    
    if (!pstatfs) {
        _ErrorHandle(EINVAL);
        return  (PX_ERROR);
    }
    
    if (__CQUFS_VOL_LOCK(pfs) != ERROR_NONE) {
        _ErrorHandle(ENXIO);
        return  (PX_ERROR);
    }
    
    __cqufs_statfs(pfs, pstatfs);
    
    __CQUFS_VOL_UNLOCK(pfs);
    
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
    PCQUFS_NODE     pcqufsn   = (PCQUFS_NODE)pfdnode->FDNODE_pvFile;
    PCQUFS_VOLUME   pfs  = (PCQUFS_VOLUME)pfdnode->FDNODE_pvFsExtern;
    
    if (!utim) {
        _ErrorHandle(EINVAL);
        return  (PX_ERROR);
    }
    
    if (__CQUFS_VOL_LOCK(pfs) != ERROR_NONE) {
        _ErrorHandle(ENXIO);
        return  (PX_ERROR);
    }
    
    if (pcqufsn) {
        pcqufsn->CQUFSN_timeAccess = utim->actime;
        pcqufsn->CQUFSN_timeChange = utim->modtime;
    
    } else {
        pfs->CQUFS_time = utim->modtime;
    }
    
    __CQUFS_VOL_UNLOCK(pfs);
    
    return  (ERROR_NONE);
}

/*********************************************************************************************************
** ��������: __littleFsIoctl
** ��������: cqufsFs ioctl ����
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
    PCQUFS_VOLUME   pfs  = (PCQUFS_VOLUME)pfdnode->FDNODE_pvFsExtern;
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
    case FIOLABELGET:                                                   /*  ��ȡ���                    */
    case FIOLABELSET:                                                   /*  ���þ��                    */
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
        *(BOOL *)lArg = pfs->CQUFS_bForceDelete;
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
** ��������: ��װ cqufs �ļ�ϵͳ��������
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
    // fileop.fo_symlink = __cqufsFsSymlink;
    // fileop.fo_readlink = __cqufsFsReadlink;

    _G_iLittleFsDrvNum = iosDrvInstallEx2(&fileop, LW_DRV_TYPE_NEW_1);     /*  ʹ�� NEW_1 ���豸��������   */

    DRIVER_LICENSE(_G_iLittleFsDrvNum, "GPL->Ver 2.0");
    DRIVER_AUTHOR(_G_iLittleFsDrvNum, "CQUFsGroup");
    DRIVER_DESCRIPTION(_G_iLittleFsDrvNum, "norflash fs driver.");

    _DebugHandle(__LOGMESSAGE_LEVEL, "norflash file system installed.\r\n");

    __fsRegister("cqufs", API_LittleFsDevCreate, LW_NULL, LW_NULL);        /*  ע���ļ�ϵͳ                */

    return  ((_G_iLittleFsDrvNum > 0) ? (ERROR_NONE) : (PX_ERROR));
}

/*********************************************************************************************************
** ��������: API_LittleFsDevCreate
** ��������: ���� cqufs �ļ�ϵͳ�豸.
** �䡡��  : pcName            �豸��(�豸�ҽӵĽڵ��ַ)
**           pblkd             ʹ�� pblkd->BLKD_pcName ��Ϊ ����С ��ʾ.
** �䡡��  : < 0 ��ʾʧ��
** ȫ�ֱ���:
** ����ģ��:
                                           API ����
*********************************************************************************************************/
#define NAMESPACE   littleFs
LW_API INT  API_LittleFsDevCreate(PCHAR   pcName, PLW_BLK_DEV  pblkd)
{
    PCQUFS_VOLUME pfs;
    size_t stMax;
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
        _ErrorHandle(EFAULT);                                           /*  Bad address                 */
        return  (PX_ERROR);
    }
    //new xmy
    // if (sscanf(pblkd->BLKD_pcName, "%zu", &stMax) != 1) {
    //     _DebugHandle(__ERRORMESSAGE_LEVEL, "max size invalidate.\r\n");
    //     _ErrorHandle(EINVAL);
    //     return  (PX_ERROR);
    // }
    //change xmy
    pfs = (PCQUFS_VOLUME)lib_malloc(sizeof(CQUFS_VOLUME));

    if (pfs == LW_NULL) {
        _DebugHandle(__ERRORMESSAGE_LEVEL, "LittleFS: system low memory.\r\n");
        _ErrorHandle(ERROR_SYSTEM_LOW_MEMORY);
        return  (PX_ERROR);
    }
    //change xmy
    lib_bzero(pfs, sizeof(CQUFS_VOLUME));                              /*  ��վ���ƿ�                */
    printf("after lib_zero-----------------------------\n");
    pfs->CQUFS_bValid = LW_TRUE;

    pfs->CQUFS_hVolLock = API_SemaphoreMCreate("LittleFS: cqufs_volume_lock", LW_PRIO_DEF_CEILING,
        LW_OPTION_WAIT_PRIORITY | LW_OPTION_DELETE_SAFE |
        LW_OPTION_INHERIT_PRIORITY | LW_OPTION_OBJECT_GLOBAL,
        LW_NULL);
    printf("2---------------------------------------\n");

    if (!pfs->CQUFS_hVolLock) {   
    //change  xmy                                  /*  �޷���������                */
        _DebugHandle(__ERRORMESSAGE_LEVEL, "can't create the lock.\r\n");
        __SHEAP_FREE(pfs);
        return  (PX_ERROR);
    }

    pfs->CQUFS_mode            = S_IFDIR | DEFAULT_DIR_PERM;
    pfs->CQUFS_uid             = getuid();
    pfs->CQUFS_gid             = getgid();
    pfs->CQUFS_time            = lib_time(LW_NULL);
    pfs->CQUFS_ulCurBlk        = 0ul;
    printf("3---------------------------------------\n");
    //xmy  be useless
//     if (stMax == 0) {
// #if LW_CFG_CPU_WORD_LENGHT == 32
//         pfs->CQUFS_ulMaxBlk = (__ARCH_ULONG_MAX / __RAM_BSIZE);
// #else
//         ps->CQUFS_ulMaxBlk = ((ULONG)(128ul * LW_CFG_GB_SIZE) / __RAM_BSIZE);
// #endif
//     } else {
//         pfs->CQUFS_ulMaxBlk = (ULONG)(stMax / __RAM_BSIZE);
//     }
    //xmy
    // struct cqufs_config* mycfg;
    //littleConfigInitialize(pfs->cqufst->cfg);
    printf("4---------------------------------------\n");
    // cqufs_mount(&(pfs->cqufst),&cfg);
    cqufs_format(&cqufs_test,&cfg);
    printf("test---------------------------------------\n");

    cqufs_mount(&cqufs_test,&cfg);

    printf("5---------------------------------------\n");
    // if (iosDevAddEx(&pfs->CQUFS_devhdrHdr, pcName, _G_iLittleFsDrvNum, DT_DIR)
    //     != ERROR_NONE) {                                                /*  ��װ�ļ�ϵͳ�豸            */
    //     printf("iosDevAddEx---------------------------------------\n");
    //     API_SemaphoreMDelete(&pfs->CQUFS_hVolLock);
    //     //xmy
    //     // cqufs_unmount(&(pfs->cqufst));
    //     cqufs_free(pfs);
    //     return  (PX_ERROR);
    // }
    printf("6---------------------------------------\n");
    _DebugFormat(__LOGMESSAGE_LEVEL, "LittleFS: target \"%s\" mount ok.\r\n", pcName);
    printf("7---------------------------------------\n");
    return  (ERROR_NONE);
    


}

/*********************************************************************************************************
** ��������: API_LittleFsDevDelete
** ��������: ɾ��һ�� cqufs �ļ�ϵͳ�豸, ����: API_LittleFsDevDelete("/mnt/cqufs0");
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
