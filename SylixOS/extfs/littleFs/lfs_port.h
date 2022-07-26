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


/*********************************************************************************************************
  ???
*********************************************************************************************************/
#if LW_CFG_MAX_VOLUMES > 0 //&& LW_CFG_LFS_EN > 0

/*********************************************************************************************************
  API
*********************************************************************************************************/
LW_API INT      API_LittleFsDrvInstall(VOID);
LW_API INT      API_LittleFsDevCreate (PCHAR  pcName, PLW_BLK_DEV pblkd);
LW_API INT      API_LittleFsDevDelete (PCHAR  pcName);

#define littlefsDrv                API_LittleFsDrvInstall
#define littlefsDevCreate          API_LittleFsDevCreate
#define littlefsDevDelete          API_LittleFsDevDelete

#endif


#endif //__LFS_PORT_H
