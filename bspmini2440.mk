#*********************************************************************************************************
#
#                                    ?1?7��?1?7?1?7?1?7?1?7?1?7?1?7?1?7?0?6?1?7?1?7?0?9
#
#                                   ?0?8?1?7?1?7?0?4?0?6?0?2?1?7?1?7?1?7?1?7?0?3?0?1
#
#                                SylixOS(TM)  LW : long wing
#
#                               Copyright All Rights Reserved
#
#--------------?1?7?0?4?1?7?1?7?1?7?0?4--------------------------------------------------------------------------------
#
# ?1?7?1?7   ?1?7?1?7   ?1?7?1?7: bspmini2440.mk
#
# ?1?7?1?7   ?1?7?1?7   ?1?7?1?7: RealEvo-IDE
#
# ?1?7?0?4?1?7?1?7?1?7?1?7?1?7?1?7?1?7?1?7?1?7: 2016 ?1?7?1?7 11 ?1?7?1?7 23 ?1?7?1?7
#
# ?1?7?1?7        ?1?7?1?7: ?1?7?1?7?1?7?0?4?1?7?1?7?1?7 RealEvo-IDE ?1?7?1?7?1?7?0?4?1?7?1?7?1?7?1?7?1?7?1?7?1?7?1?7?1?7 Makefile ?1?7?1?7?1?7?1?1?1?7?1?7?1?7?1?7?1?7?1?7?0?6?1?7?1?7?1?0?1?7
#*********************************************************************************************************

#*********************************************************************************************************
# Clear setting
#*********************************************************************************************************
include $(CLEAR_VARS_MK)

#*********************************************************************************************************
# Target
#*********************************************************************************************************
LOCAL_TARGET_NAME := bspmini2440.elf

#*********************************************************************************************************
# Source list
#*********************************************************************************************************
LOCAL_SRCS :=  \
SylixOS/bsp/startup.S \
SylixOS/bsp/bspInit.c \
SylixOS/bsp/bspLib.c \
SylixOS/bsp/targetInit.c \
SylixOS/driver/dma/samsungdma.c \
SylixOS/driver/gpio/s3c2440_gpio.c \
SylixOS/driver/i2c/samsungi2c.c \
SylixOS/driver/lcd/s3c2440a_lcd.c \
SylixOS/driver/mtd/nand/k9f1g08.c \
SylixOS/driver/mtd/nand/nand.c \
SylixOS/driver/mtd/nand/s3c24xx_nand.c \
SylixOS/driver/mtd/nor/fake_nor.c \
SylixOS/driver/mtd/nor/nor.c \
SylixOS/driver/mtd/nor/nor_cmd.c \
SylixOS/driver/mtd/nor/nor_util.c \
SylixOS/driver/netif/dm9000x.c \
SylixOS/driver/pm/s3c2440a_pm.c \
SylixOS/driver/rtc/rtc.c \
SylixOS/driver/sdi/mciLib.c \
SylixOS/driver/sdi/s3csdi.c \
SylixOS/driver/sdi/sdInit.c \
SylixOS/driver/timer/timer.c \
SylixOS/driver/touchscr/s3c_onewire.c \
SylixOS/driver/touchscr/touchscr.c \
SylixOS/driver/tty/samsungtty.c \
SylixOS/driver/tty/uart.c \
SylixOS/extfs/cquFs/cqufs.c \
SylixOS/extfs/cquFs/cqufs_util.c \
SylixOS/extfs/cquFs/cuqfs_port.c \
SylixOS/extfs/hoitFs/hoitFs.c \
SylixOS/extfs/hoitFs/hoitFsCache.c \
SylixOS/extfs/hoitFs/hoitFsCmd.c \
SylixOS/extfs/hoitFs/hoitFsFDLib.c \
SylixOS/extfs/hoitFs/hoitFsGC.c \
SylixOS/extfs/hoitFs/hoitFsLib.c \
SylixOS/extfs/hoitFs/hoitFsLog.c \
SylixOS/extfs/hoitFs/hoitFsTest.c \
SylixOS/extfs/hoitFs/hoitFsTree.c \
SylixOS/extfs/hoitFs/hoitFsTreeUtil.c \
SylixOS/extfs/hoitFs/hoitMergeBuffer.c \
SylixOS/extfs/spifFs/spifFs.c \
SylixOS/extfs/spifFs/spifFsCache.c \
SylixOS/extfs/spifFs/spifFsCmd.c \
SylixOS/extfs/spifFs/spifFsFDLib.c \
SylixOS/extfs/spifFs/spifFsGC.c \
SylixOS/extfs/spifFs/spifFsGlue.c \
SylixOS/extfs/spifFs/spifFsLib.c \
SylixOS/extfs/spifFs/spifFsVerify.c \
SylixOS/extfs/tools/fstester/fstester.c \
SylixOS/extfs/tools/fstester/functionality.c \
SylixOS/extfs/tools/list/iter.c \
SylixOS/extfs/tools/list/list.c \
SylixOS/extfs/tools/list/list_test.c \
SylixOS/user/main.c

#*********************************************************************************************************
# Header file search path (eg. LOCAL_INC_PATH := -I"Your header files search path")
#*********************************************************************************************************
LOCAL_INC_PATH := \
-I"./SylixOS" \
-I"./SylixOS/bsp"

#*********************************************************************************************************
# Pre-defined macro (eg. -DYOUR_MARCO=1)
#*********************************************************************************************************
LOCAL_DSYMBOL := \
-D__BOOT_INRAM=1

#*********************************************************************************************************
# Compiler flags
#*********************************************************************************************************
LOCAL_CFLAGS   := 
LOCAL_CXXFLAGS := 

#*********************************************************************************************************
# Depend library (eg. LOCAL_DEPEND_LIB := -la LOCAL_DEPEND_LIB_PATH := -L"Your library search path")
#*********************************************************************************************************
LOCAL_DEPEND_LIB      := 
LOCAL_DEPEND_LIB_PATH := 

#*********************************************************************************************************
# Link script file
#*********************************************************************************************************
LOCAL_LD_SCRIPT := SylixOSBSP.ld

#*********************************************************************************************************
# C++ config
#*********************************************************************************************************
LOCAL_USE_CXX        := no
LOCAL_USE_CXX_EXCEPT := no

#*********************************************************************************************************
# Code coverage config
#*********************************************************************************************************
LOCAL_USE_GCOV := no

#*********************************************************************************************************
# OpenMP config
#*********************************************************************************************************
LOCAL_USE_OMP := no

#*********************************************************************************************************
# User link command
#*********************************************************************************************************
LOCAL_PRE_LINK_CMD   := 
LOCAL_POST_LINK_CMD  := 
LOCAL_PRE_STRIP_CMD  := 
LOCAL_POST_STRIP_CMD := 

include $(BSP_MK)

#*********************************************************************************************************
# End
#*********************************************************************************************************
