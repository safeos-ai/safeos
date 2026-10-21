// more: show a file, or standard input, one screen at a time.   usage: more [-N] [file...]
// The keys are read from the console and not from standard input, so it works at the end of a pipe: cat README | more.
// Enter shows the next screen, q and Enter stops. When standard output is not the console, more just copies.
#include "types.h"
#include "stat.h"
#include "user.h"
#include "fcntl.h"

static char buf[512];
static int page = 20;
static int kb = -1;           // the console: the prompt goes to it, and the keys come from it
static int paging;            // 1 if standard output is the console

static int
wait_key(void)                // 1 to go on, 0 to stop
{
  static char prompt[] = "--More-- (Enter: next screen, q: quit) ";
  char ans[64];
  int n;

  write(kb, prompt, strlen(prompt));
  n = read(kb, ans, sizeof(ans));
  if(n <= 0 || ans[0] == 'q' || ans[0] == 'Q')
    return 0;
  return 1;
}

static int
show(int fd)                  // 1 to go on with the next file, 0 if the reader stopped
{
  int n, i, start, lines = 0;

  while((n = read(fd, buf, sizeof(buf))) > 0){
    start = 0;
    for(i = 0; i < n; i++){
      if(buf[i] != '\n')
        continue;
      write(1, buf + start, i + 1 - start);
      start = i + 1;
      if(paging && ++lines >= page){
        lines = 0;
        if(!wait_key())
          return 0;
      }
    }
    if(start < n)
      write(1, buf + start, n - start);     // a line that goes on into the next chunk
  }
  return 1;
}

int
main(int argc, char *argv[])
{
  struct stat st;
  int i = 1, first, fd;

  if(argc > 1 && argv[1][0] == '-' && argv[1][1] >= '0' && argv[1][1] <= '9'){
    page = atoi(argv[1] + 1);
    i = 2;
  }
  if(page < 1){
    printf(2, "usage: more [-N] [file...]   (N is 1 or more)\n");
    exit();
  }
  paging = fstat(1, &st) == 0 && st.type == T_DEV;
  if(paging && (kb = open("/console", O_RDWR)) < 0){
    printf(2, "more: cannot open the console\n");
    exit();
  }
  if(i >= argc){
    if(fstat(0, &st) == 0 && st.type == T_DEV){      // the keyboard: there is nothing to show
      printf(2, "usage: more [-N] [file...]   (or: cat file | more)\n");
      exit();
    }
    show(0);
    exit();
  }
  first = i;
  for(; i < argc; i++){
    fd = open(argv[i], O_RDONLY);
    if(fd < 0){
      printf(2, "more: cannot open %s\n", argv[i]);
      continue;
    }
    if(argc - first > 1)
      printf(1, "==> %s <==\n", argv[i]);
    if(!show(fd)){
      close(fd);
      break;
    }
    close(fd);
  }
  exit();
}
