#include "types.h"
#include "stat.h"
#include "user.h"

char buf[2048];

int
main(void)
{
  int pid1, pid2, pid3;
  int pfds[2];

  pid1 = fork();
  if(pid1 == 0)
    for(;;)
      ;
  pid2 = fork();
  if(pid2 == 0)
    for(;;)
      ;
  pipe(pfds);
  pid3 = fork();
  if(pid3 == 0){
    close(pfds[0]);
    if(write(pfds[1], "x", 1) != 1)
      printf(1, "write error\n");
    close(pfds[1]);
    for(;;)
      ;
  }
  close(pfds[1]);
  if(read(pfds[0], buf, sizeof(buf)) != 1){
    printf(1, "read error\n");
    exit();
  }
  close(pfds[0]);
  printf(1, "got the byte\n");
  kill(pid1);
  kill(pid2);
  kill(pid3);
  wait();
  wait();
  wait();
  printf(1, "preempttest ok\n");
  exit();
}
