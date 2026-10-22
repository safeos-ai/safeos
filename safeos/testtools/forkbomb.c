// forkbomb: a bounded fork storm, to test killgroup against processes that are busy forking.
// It builds 2^levels processes (default 4, so 16), and then each one repeatedly forks a child that
// exits at once, until life ticks have passed. The process table cannot fill: at most 2 * 2^levels
// processes exist at once, and levels is capped at 4. (A shell whose fork fails panics, and then init
// cannot start a new one, so a test that fills the table can crash the kernel.)
// usage: forkbomb [life_ticks [levels 1-4]]
#include "types.h"
#include "stat.h"
#include "user.h"

int
main(int argc, char *argv[])
{
  int life = 20000, levels = 4, i, pid, start;

  if(argc > 1)
    life = atoi(argv[1]);
  if(argc > 2)
    levels = atoi(argv[2]);
  if(life < 1 || levels < 1 || levels > 4){
    printf(1, "usage: forkbomb [life_ticks [levels 1-4]]\n");
    exit();
  }
  printf(1, "forkbomb: %d processes forking for %d ticks\n", 1 << levels, life);
  start = uptime();
  for(i = 0; i < levels; i++)
    if(fork() < 0)
      break;                      // every process continues the loop: 2^levels in all
  while(uptime() - start < life){
    pid = fork();
    if(pid == 0)
      exit();                     // the child dies at once
    if(pid > 0)
      wait();
    else
      sleep(1);                   // the fork was refused (the group is being killed): wait and retry
  }
  while(wait() >= 0)
    ;
  exit();
}
