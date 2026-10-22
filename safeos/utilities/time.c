// time: run a command and print how many timer ticks it took.
#include "types.h"
#include "stat.h"
#include "user.h"

int
main(int argc, char *argv[])
{
  int start, end, pid;

  if(argc < 2){
    printf(2, "usage: time command [args...]\n");
    exit();
  }
  start = uptime();
  pid = fork();
  if(pid < 0){
    printf(2, "time: fork failed\n");
    exit();
  }
  if(pid == 0){
    exec(argv[1], argv + 1);
    printf(2, "time: exec %s failed\n", argv[1]);
    exit();
  }
  wait();
  end = uptime();
  printf(1, "time: %d ticks\n", end - start);
  exit();
}
