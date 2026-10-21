// mv: move or rename a file, with link and unlink.   usage: mv <source> <destination>
// The file keeps its inode, so nothing is copied. Regular files only: xv6 cannot link a directory.
// A destination that exists is not overwritten. If the destination is a directory, the file goes in it.
#include "types.h"
#include "stat.h"
#include "user.h"

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
  int n;

  if(argc != 3){
    printf(2, "usage: mv <source> <destination>\n");
    exit();
  }
  if(stat(argv[1], &ss) < 0){
    printf(2, "mv: cannot find %s\n", argv[1]);
    exit();
  }
  if(ss.type == T_DIR){
    printf(2, "mv: %s is a directory: xv6 cannot move a directory\n", argv[1]);
    exit();
  }
  if(ss.type != T_FILE){
    printf(2, "mv: %s is not a regular file\n", argv[1]);
    exit();
  }
  dst = argv[2];
  if(stat(dst, &ds) == 0 && ds.type == T_DIR){          // into a directory, under the source's name
    n = strlen(dst);
    if(n + 1 + strlen(base_of(argv[1])) >= (int)sizeof(path)){
      printf(2, "mv: the destination name is too long\n");
      exit();
    }
    memmove(path, dst, n);
    path[n] = '/';
    strcpy(path + n + 1, base_of(argv[1]));
    dst = path;
  }
  if(stat(dst, &ds) == 0){
    if(ds.type == T_FILE && ds.dev == ss.dev && ds.ino == ss.ino)
      printf(2, "mv: %s and %s are the same file\n", argv[1], dst);
    else
      printf(2, "mv: %s already exists: it is not overwritten\n", dst);
    exit();
  }
  if(link(argv[1], dst) < 0){
    printf(2, "mv: cannot link %s to %s\n", argv[1], dst);
    exit();
  }
  if(unlink(argv[1]) < 0)
    printf(2, "mv: %s is now also %s, but its old name could not be removed\n", argv[1], dst);
  exit();
}
