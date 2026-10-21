// head: print the first lines of files, or of standard input.   usage: head [-n N | -N] [file...]
#include "types.h"
#include "stat.h"
#include "user.h"
#include "fcntl.h"

static char buf[512];

static void
head(int fd, int lines)
{
  int n, i, seen = 0;

  while((n = read(fd, buf, sizeof(buf))) > 0){
    for(i = 0; i < n; i++){
      if(buf[i] == '\n' && ++seen == lines){
        write(1, buf, i + 1);
        return;
      }
    }
    write(1, buf, n);
  }
}

int
main(int argc, char *argv[])
{
  int lines = 10, i = 1, first, fd;

  if(argc > 2 && strcmp(argv[1], "-n") == 0){
    lines = atoi(argv[2]);
    i = 3;
  } else if(argc > 1 && argv[1][0] == '-' && argv[1][1] >= '0' && argv[1][1] <= '9'){
    lines = atoi(argv[1] + 1);
    i = 2;
  }
  if(lines < 1){
    printf(2, "usage: head [-n N | -N] [file...]   (N is 1 or more)\n");
    exit();
  }
  if(i >= argc){
    head(0, lines);
    exit();
  }
  first = i;
  for(; i < argc; i++){
    fd = open(argv[i], O_RDONLY);
    if(fd < 0){
      printf(2, "head: cannot open %s\n", argv[i]);
      continue;
    }
    if(argc - first > 1){
      if(i > first)
        printf(1, "\n");
      printf(1, "==> %s <==\n", argv[i]);
    }
    head(fd, lines);
    close(fd);
  }
  exit();
}
