#include "types.h"
#include "stat.h"
#include "user.h"

char buf[512];

void
cat(int fd)
{
  int n;
  struct stat in, out;

  if(fstat(fd, &in) == 0 && fstat(1, &out) == 0 && in.type == T_FILE && out.type == T_FILE &&
     in.dev == out.dev && in.ino == out.ino){
    printf(2, "cat: input file is output file\n");   // to descriptor 2: descriptor 1 may be the file itself
    exit();
  }

  while((n = read(fd, buf, sizeof(buf))) > 0) {
    if (write(1, buf, n) != n) {
      printf(1, "cat: write error\n");
      exit();
    }
  }
  if(n < 0){
    printf(1, "cat: read error\n");
    exit();
  }
}

int
main(int argc, char *argv[])
{
  int fd, i;

  if(argc <= 1){
    cat(0);
    exit();
  }

  for(i = 1; i < argc; i++){
    if((fd = open(argv[i], 0)) < 0){
      printf(1, "cat: cannot open %s\n", argv[i]);
      exit();
    }
    cat(fd);
    close(fd);
  }
  exit();
}
