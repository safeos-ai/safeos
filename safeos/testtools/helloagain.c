/*#include "stdio.h"

int
main(void)
{

  fprintf(1, "hello (running on cpu%d)\n", getcpu());
  //fprintf(stdout, "hello\n");
  fprintf(stdout, "world\n");
  fprintf(stdout, "again\n");
  sleep(100);
  exit();
}*/
#include "stdio.h"

int
main(void)
{
  int pid;

  pid = fork();
  if(pid < 0){
    fprintf(2, "helloagain: fork failed\n");
    exit();
  }

  if(pid == 0){
    // child: does all the printing
    fprintf(1, "hello (running on cpu%d)\n", getcpu());
    fprintf(stdout, "world\n");
    fprintf(stdout, "again\n");
    sleep(100);
    exit();
  }

  // parent: only waits for its child, then exits
  wait();
  exit();
}
