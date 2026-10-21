// rmdir: remove empty directories.   usage: rmdir <directory>...
#include "types.h"
#include "stat.h"
#include "user.h"

int
main(int argc, char *argv[])
{
  int i;
  struct stat st;

  if(argc < 2){
    printf(2, "usage: rmdir <directory>...\n");
    exit();
  }
  for(i = 1; i < argc; i++){
    if(stat(argv[i], &st) < 0)
      printf(2, "rmdir: %s: no such file or directory\n", argv[i]);
    else if(st.type != T_DIR)
      printf(2, "rmdir: %s: not a directory (use rm for a file)\n", argv[i]);
    else if(unlink(argv[i]) < 0)
      printf(2, "rmdir: %s: cannot remove it (is it empty?)\n", argv[i]);
  }
  exit();
}
