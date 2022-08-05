//#define  __SYLIXOS_STDIO
//#define  __SYLIXOS_KERNEL

#include "unistd.h"
#include "sys/utsname.h"
#include "stdlib.h"
//#include "shell/fsLib/ttinyShellFsCmd.h"
//#include "appl/editors/vi/src/vi.c"
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


    PCHAR mountcmd[5]={"mount","-t","lfs","/root/1","/mnt/lfs"};
    int mountargs=5;
    __tshellFsCmdMount(mountargs,mountcmd);
    printf("@@__tshellFsCmdMount end!\n\n");


//    PCHAR mountcmd[5]={"mount","-t","ramfs","/root/1","/mnt/ramfs"};
//    int mountargs=5;
//    __tshellFsCmdMount(mountargs,mountcmd);
//    printf("@@__tshellFsCmdMount end!\n\n");


//    PCHAR cdcmd[2]={"cd","/mnt/lfs"};
//    int cdargs=2;
//    __tshellFsCmdCd(cdargs,cdcmd);
//    printf("@@__tshellFsCmdCd end!\n\n");
//
//
    PCHAR mkdircmd[2]={"mkdir","/mnt/lfs/d1"};
    int mkdirargs=2;
    __tshellFsCmdMkdir(mkdirargs,mkdircmd);
    printf("@@__tshellFsCmdMkdir end!\n\n");


    PCHAR touchcmd[2]={"touch","/mnt/lfs/f1"};
    int touchargs=2;
    __tshellFsCmdTouch(touchargs,touchcmd);
    printf("@@__tshellFsCmdTouch end!\n\n");

    PCHAR lncmd[3]={"ln", "/mnt/lfs/f1","/mnt/lfs/f2"};
    int lnargs = 3;
    __tshellFsCmdLn(lnargs, lncmd);
    printf("@@__tshellFsCmdLn end!\n\n");

    PCHAR catcmd[2]={"cat", "/mnt/lfs/f2"};
    int catargs = 2;
    __tshellFsCmdCat( catargs, catcmd);
    printf("@@__tshellFsCmdCat end!\n\n");
//    PCHAR vicmd[2]={"vi","/mnt/lfs3/vifile"};
//    int viargs=2;
//    vi_main(viargs,vicmd);
//    printf("vi_main end!\n\n");


//    PCHAR cdcmd2[2]={"cd","/mnt/lfs2/zjw100"};
//    __tshellFsCmdCd(cdargs,cdcmd2);


//    PCHAR cdcmd[2]={"cd","/mnt/lfs2"};
//    int cdargs=2;
//    __tshellFsCmdCd(cdargs,cdcmd);
//    printf("__tshellFsCmdCd end!\n");


    Lw_TShell_Create(STDOUT_FILENO, LW_OPTION_TSHELL_PROMPT_FULL | LW_OPTION_TSHELL_VT100);

    return  (0);
}
