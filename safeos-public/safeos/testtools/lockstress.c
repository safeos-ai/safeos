// lockstress: provoke the create()/link() lock-order deadlock in iput().
// Creators repeatedly create and remove lsd/N while linkers repeatedly link lsd/base to
// lsd/N. If the kernel can deadlock, every process ends up asleep and the output stops.
// usage: lockstress [iterations [creators [linkers]]]
#include "types.h"
#include "stat.h"
#include "user.h"
#include "fcntl.h"

#define DIR   "lsd"
#define BASE  "lsd/base"
#define NAME  "lsd/N"

static void
creator(int id, int iters)
{
  int i, fd;

  for(i = 1; i <= iters; i++){
    fd = open(NAME, O_CREATE | O_RDWR);
    if(fd >= 0)
      close(fd);
    unlink(NAME);
    if(i % 1000 == 0)
      printf(1, "creator %d: %d\n", id, i);
  }
  exit();
}

static void
linker(int id, int iters)
{
  int i;

  for(i = 1; i <= iters; i++){
    link(BASE, NAME);
    unlink(NAME);
    if(i % 1000 == 0)
      printf(1, "linker %d: %d\n", id, i);
  }
  exit();
}

int
main(int argc, char *argv[])
{
  int iters = 20000, nc = 2, nl = 2;
  int i, fd, pid, started = 0, t0;

  if(argc > 1)
    iters = atoi(argv[1]);
  if(argc > 2)
    nc = atoi(argv[2]);
  if(argc > 3)
    nl = atoi(argv[3]);
  if(iters < 1 || nc < 1 || nc > 8 || nl < 1 || nl > 8){
    printf(1, "usage: lockstress [iterations [creators 1-8 [linkers 1-8]]]\n");
    exit();
  }

  mkdir(DIR);
  unlink(NAME);
  unlink(BASE);
  fd = open(BASE, O_CREATE | O_RDWR);
  if(fd < 0){
    printf(1, "lockstress: cannot create %s\n", BASE);
    exit();
  }
  write(fd, "x", 1);
  close(fd);

  printf(1, "lockstress: %d creators, %d linkers, %d iterations each\n", nc, nl, iters);
  t0 = uptime();
  for(i = 0; i < nc + nl; i++){
    pid = fork();
    if(pid < 0){
      printf(1, "lockstress: fork failed\n");
      break;
    }
    if(pid == 0){
      if(i < nc)
        creator(i, iters);
      else
        linker(i - nc, iters);
    }
    started++;
  }
  for(i = 0; i < started; i++)
    wait();
  unlink(NAME);
  unlink(BASE);
  unlink(DIR);
  printf(1, "lockstress: done, %d ticks\n", uptime() - t0);
  exit();
}
