// testapp: a small program to test installation and reports.
//   testapp                  print one line
//   testapp talk <n>         print n lines (to try the stdout limit)
//   testapp burn [ticks]     use the CPU for that many ticks (to try the cputime limit)
//   testapp mem [pages]      grow by that many 4 KB pages (8000 by default), touch each, and hold them (to try the memory limit)
//   testapp report <text>    add one record to its report log (write_report)
//   testapp readreport       print its report log (read_report)
//   testapp clearreport      empty the log (clear_report)
//   testapp fillreport       add reports until the kernel refuses
//   testapp longreport       try a text that is too long
//   testapp badreport        report a text with an escape sequence and a control byte
//   testapp plainopen        try to open the report file with plain open
//   testapp run <args>       run testapp again with these arguments: a child of the same app
//   testapp sh <file>        run a script (sh <file>) as a child: everything it starts must stay in this app's group
//   testapp tamper           try four things that must be refused
#include "types.h"
#include "stat.h"
#include "user.h"
#include "fcntl.h"

#define REPORT "/apps/testapp/report/status.txt"

static char text[256];
static char big[4097];

static void
tamper(void)
{
  int fd;

  fd = open("/apps/testapp/report/other", O_CREATE | O_RDWR);
  if(fd >= 0){
    close(fd);
    unlink("/apps/testapp/report/other");
  }
  printf(1, "create a file in report/: %s\n", fd < 0 ? "refused" : "ALLOWED");
  if(link(REPORT, "/stolen") == 0){
    unlink("/stolen");
    printf(1, "a second name for status.txt: ALLOWED\n");
  } else
    printf(1, "a second name for status.txt: refused\n");
  printf(1, "remove status.txt: %s\n", unlink(REPORT) < 0 ? "refused" : "ALLOWED");
  fd = open("/apps/testapp/testapp", O_RDWR);
  if(fd >= 0)
    close(fd);
  printf(1, "write the program file: %s\n", fd < 0 ? "refused" : "ALLOWED");
}

static void
plainopen(void)
{
  int fd;

  fd = open(REPORT, O_RDONLY);
  if(fd >= 0)
    close(fd);
  printf(1, "open status.txt for reading: %s\n", fd < 0 ? "refused" : "ALLOWED");
  fd = open(REPORT, O_RDWR);
  if(fd >= 0)
    close(fd);
  printf(1, "open status.txt for writing: %s\n", fd < 0 ? "refused" : "ALLOWED");
  fd = open("/apps/testapp/report", O_RDONLY);
  if(fd >= 0)
    close(fd);
  printf(1, "open the report directory: %s\n", fd < 0 ? "refused" : "ALLOWED");
}

int
main(int argc, char *argv[])
{
  int i, j, n, r, t0, ticks = 300;
  volatile int x = 0;

  if(argc > 2 && strcmp(argv[1], "talk") == 0){
    n = atoi(argv[2]);
    for(i = 0; i < n; i++)
      printf(1, "testapp line %d\n", i);
    exit();
  }
  if(argc > 1 && strcmp(argv[1], "burn") == 0){
    if(argc > 2)
      ticks = atoi(argv[2]);
    t0 = uptime();
    while(uptime() - t0 < ticks)
      for(i = 0; i < 100000; i++)
        x += i;
    exit();
  }
  if(argc > 1 && strcmp(argv[1], "mem") == 0){      // grow by that many pages and hold them, to try the memory limit
    char *q;
    int pages = 8000;

    if(argc > 2)
      pages = atoi(argv[2]);
    for(i = 0; i < pages; i++){
      q = sbrk(4096);
      if(q == (char*)-1)
        break;
      q[0] = 1;                                     // touch the page so that it is really mapped
    }
    printf(1, "testapp: holding %d pages (%d KB)\n", i, i * 4);
    t0 = uptime();
    while(uptime() - t0 < ticks)
      sleep(10);
    exit();
  }
  if(argc > 2 && strcmp(argv[1], "report") == 0){
    n = 0;
    for(i = 2; i < argc && n < 191; i++){        // the words, joined with spaces
      if(i > 2 && n < 191)
        text[n++] = ' ';
      for(j = 0; argv[i][j] && n < 191; j++)
        text[n++] = argv[i][j];
    }
    r = write_report(text, n);
    printf(1, "testapp: write_report returned %d%s\n", r,
           r == 0 ? "" : r == -2 ? " (the log is full)" : r == -1 ? " (not an installed app)" : "");
    exit();
  }
  if(argc > 1 && strcmp(argv[1], "readreport") == 0){
    n = read_report(big, 4096);
    if(n < 0)
      printf(1, "testapp: read_report returned %d\n", n);
    else if(n == 0)
      printf(1, "testapp: the report log is empty\n");
    else
      write(1, big, n);
    exit();
  }
  if(argc > 1 && strcmp(argv[1], "clearreport") == 0){
    printf(1, "testapp: clear_report returned %d\n", clear_report());
    exit();
  }
  if(argc > 1 && strcmp(argv[1], "fillreport") == 0){
    r = 0;
    for(i = 1; i <= 20 && r == 0; i++){
      n = 0;
      text[n++] = 'f'; text[n++] = 'i'; text[n++] = 'l'; text[n++] = 'l'; text[n++] = ' ';
      if(i >= 10)
        text[n++] = '0' + i / 10;
      text[n++] = '0' + i % 10;
      r = write_report(text, n);
    }
    printf(1, "testapp: filled %d records, then write_report returned %d\n", r == 0 ? 20 : i - 2, r);
    exit();
  }
  if(argc > 1 && strcmp(argv[1], "longreport") == 0){
    for(i = 0; i < 192; i++)
      text[i] = 'x';
    printf(1, "testapp: a text of 192 bytes: write_report returned %d\n", write_report(text, 192));
    printf(1, "testapp: a text of 191 bytes: write_report returned %d\n", write_report(text, 191));
    exit();
  }
  if(argc > 1 && strcmp(argv[1], "badreport") == 0){
    static char s[] = "plain \033[31mred\001 end";
    printf(1, "testapp: write_report returned %d\n", write_report(s, strlen(s)));
    exit();
  }
  if(argc > 1 && strcmp(argv[1], "plainopen") == 0){
    plainopen();
    exit();
  }
  if(argc > 2 && strcmp(argv[1], "run") == 0){      // a child of the same app: it runs testapp again with the remaining words
    if(fork() == 0){
      argv[1] = "testapp";
      exec("testapp", &argv[1]);
      printf(2, "testapp: exec failed\n");
      exit();
    }
    wait();
    exit();
  }
  if(argc > 2 && strcmp(argv[1], "sh") == 0){       // a script run by this app: the group rule decides where everything it starts goes
    char *av[3];

    if(fork() == 0){
      av[0] = "sh";
      av[1] = argv[2];
      av[2] = 0;
      exec("sh", av);
      printf(2, "%s: exec sh failed\n", argv[0]);
      exit();
    }
    wait();
    printf(1, "%s: the script ended\n", argv[0]);
    exit();
  }
  if(argc > 1 && strcmp(argv[1], "tamper") == 0){
    tamper();
    exit();
  }
  printf(1, "testapp: I am an installed app\n");
  exit();
}
