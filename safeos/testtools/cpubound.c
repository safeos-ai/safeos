#include "types.h"
#include "stat.h"
#include "user.h"

#define NCHILD 4
#define WORK   2000000000   // iterations per child; tune so 1 CPU takes a few hundred ticks
#define REPORT 500000000
int
main(void)
{
  int i, j, pid;
  volatile int x = 0;

  for(i = 0; i < NCHILD; i++){
    pid = fork();
    if(pid < 0){
      printf(1, "cpubound: fork failed\n");
      exit();
    }
    if(pid == 0){
      for(j = 0; j < WORK; j++){
	      x += j;
	      if (j % REPORT == 0)
		      printf(1, "j=%d\n", j);
      }
      exit();
    }
  }
  for(i = 0; i < NCHILD; i++)
    wait();
  exit();
}
