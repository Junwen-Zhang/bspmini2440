//#define  __SYLIXOS_STDIO
//#define  __SYLIXOS_KERNEL

#include "unistd.h"
#include "sys/utsname.h"
#include "stdlib.h"
#include "shell/fsLib/ttinyShellFsCmd.h"
//#include "extfs/littleFs/lfs_port.h"
//#include "fs/romFs/romFs.h"

int  t_main (void)
{
    struct utsname  name;

    uname(&name);

    printf("sysname  : %s\n", name.sysname);
    printf("nodename : %s\n", name.nodename);
    printf("release  : %s\n", name.release);
    printf("version  : %s\n", name.version);
    printf("machine  : %s\n", name.machine);


    PCHAR mountcmd[5]={"mount","-t","lfs","/root/1","/mnt/lfs2"};
    int mountargs=5;
    __tshellFsCmdMount(mountargs,mountcmd);
    printf("__tshellFsCmdMount end!\n");


//    PCHAR cdcmd[2]={"cd","/mnt/lfs2"};
//    int cdargs=2;
//    __tshellFsCmdCd(cdargs,cdcmd);


    PCHAR mkdircmd[2]={"mkdir","/mnt/lfs2/zjw100"};
    int mkdirargs=2;
    __tshellFsCmdMkdir(mkdirargs,mkdircmd);
    printf("__tshellFsCmdMkdir end!\n");


    PCHAR cdcmd[2]={"cd","/mnt/lfs2"};
    int cdargs=2;
    __tshellFsCmdCd(cdargs,cdcmd);
    printf("__tshellFsCmdCd end!\n");


    Lw_TShell_Create(STDOUT_FILENO, LW_OPTION_TSHELL_PROMPT_FULL | LW_OPTION_TSHELL_VT100);

    return  (0);
}
