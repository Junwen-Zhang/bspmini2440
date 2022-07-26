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
** 描        述: LittleFs与VFS的接口文件
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
