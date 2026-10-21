// cp: copy a file.   usage: cp <source> <destination>
// If the destination is a directory, the copy goes in it under the source's name. An existing file is overwritten.
#include "types.h"
#include "stat.h"
#include "user.h"
#include "fcntl.h"

static char buf[512];

static char*
base_of(char *path)
{
  char *p;

  for(p = path + strlen(path); p >= path && *p != '/'; p--)
    ;
  return p + 1;
}

int
main(int argc, char *argv[])
{
  struct stat ss, ds;
  char path[128], *dst;
  int in, out, n;

  if(argc != 3){
    printf(2, "usage: cp <source> <destination>\n");
    exit();
  }
  if(stat(argv[1], &ss) < 0){
    printf(2, "cp: cannot open %s\n", argv[1]);
    exit();
  }
  if(ss.type == T_DIR){
    printf(2, "cp: %s is a directory (not copied)\n", argv[1]);
    exit();
  }
  if(ss.type != T_FILE){
    printf(2, "cp: %s is not a regular file\n", argv[1]);
    exit();
  }
  dst = argv[2];
  if(stat(dst, &ds) == 0 && ds.type == T_DIR){          // into a directory, under the source's name
    n = strlen(dst);
    if(n + 1 + strlen(base_of(argv[1])) >= (int)sizeof(path)){
      printf(2, "cp: the destination name is too long\n");
      exit();
    }
    memmove(path, dst, n);
    path[n] = '/';
    strcpy(path + n + 1, base_of(argv[1]));
    dst = path;
  }
  if(stat(dst, &ds) == 0){
    if(ds.type == T_DIR){
      printf(2, "cp: %s is a directory\n", dst);
      exit();
    }
    if(ds.dev == ss.dev && ds.ino == ss.ino){
      printf(2, "cp: %s and %s are the same file\n", argv[1], dst);
      exit();
    }
  }
  if((in = open(argv[1], O_RDONLY)) < 0){
    printf(2, "cp: cannot open %s\n", argv[1]);
    exit();
  }
  if((out = open(dst, O_CREATE | O_WRONLY | O_TRUNC)) < 0){
    printf(2, "cp: cannot create %s\n", dst);
    close(in);
    exit();
  }
  while((n = read(in, buf, sizeof(buf))) > 0){
    if(write(out, buf, n) != n){
      printf(2, "cp: write error on %s\n", dst);
      break;
    }
  }
  close(in);
  close(out);
  exit();
}
