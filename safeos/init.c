// init: The initial user-level program

#include "types.h"
#include "stat.h"
#include "user.h"
#include "fcntl.h"

char *argv[] = { "sh", 0 };
int safeos = 0;
int
main(void)
{
  int pid, wpid, fd;
  char c;

  if(open("console", O_RDWR) < 0){
    mknod("console", 1, 1);
    open("console", O_RDWR);
  }
  dup(0);  // stdout
  dup(0);  // stderr
  fd = open("kernel", O_RDONLY);       // the device sh reads to tell the kernels apart: made once, by whichever kernel boots first
  if(fd < 0){
    mknod("kernel", 2, 0);
    fd = open("kernel", O_RDONLY);
  }
  if(fd >= 0){
    if(read(fd, &c, 1) >= 0)           // only the SafeOS kernel has a driver behind /kernel: on stock xv6 the read fails
      safeos = 1;
    close(fd);
  }

  for(;;){
    printf(1, "init: starting sh\n");
    if (safeos)
      printf(1, "please more README to try test cases\n");
    pid = fork();
    if(pid < 0){
      printf(1, "init: fork failed\n");
      exit();
    }
    if(pid == 0){
      exec("sh", argv);
      printf(1, "init: exec sh failed\n");
      exit();
    }
    while((wpid=wait()) >= 0 && wpid != pid)
      printf(1, "zombie!\n");
  }
}
