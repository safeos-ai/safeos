// grptest: stays alive, so the Owner can list the group it runs in and what the group uses.
//   grptest [ticks]               sleep (default 1000000 ticks)
//   grptest run [ticks]           also start slowprint, a utility, as a child: it should join this group
//   grptest burn [ticks]          use the CPU for the whole time
//   grptest mem <pages> [ticks]   hold that many extra pages, then sleep
// Run it under other names with ln: appnap is listed as an App, toolnap as a utility.
#include "types.h"
#include "stat.h"
#include "user.h"

int
main(int argc, char *argv[])
{
  int ticks = 1000000, pid = 0, i, j, pages, t0;
  volatile int x = 0;
  char *av[2], *mem;

  if(argc > 1 && strcmp(argv[1], "run") == 0){
    pid = fork();
    if(pid == 0){
      av[0] = "slowprint";
      av[1] = 0;
      exec("slowprint", av);
      exit();
    }
    if(argc > 2)
      ticks = atoi(argv[2]);
  } else if(argc > 1 && strcmp(argv[1], "burn") == 0){
    if(argc > 2)
      ticks = atoi(argv[2]);
    t0 = uptime();
    while(uptime() - t0 < ticks)
      for(j = 0; j < 100000; j++)
        x += j;
    exit();
  } else if(argc > 2 && strcmp(argv[1], "mem") == 0){
    pages = atoi(argv[2]);
    if(argc > 3)
      ticks = atoi(argv[3]);
    mem = sbrk(pages * 4096);
    if(mem == (char*)-1){
      printf(1, "grptest: cannot get %d pages\n", pages);
      exit();
    }
    for(i = 0; i < pages; i++)
      mem[i * 4096] = 1;               // touch each page, so it is really held
  } else if(argc > 1)
    ticks = atoi(argv[1]);
  sleep(ticks);
  while(pid > 0 && wait() >= 0)
    ;
  exit();
}
