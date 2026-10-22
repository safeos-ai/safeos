// touch: create empty files.   usage: touch <file>...
// A file that exists is left as it is: xv6 files carry no times, so there is nothing to update.
#include "types.h"
#include "stat.h"
#include "user.h"
#include "fcntl.h"

int
main(int argc, char *argv[])
{
  int i, fd;

  if(argc < 2){
    printf(2, "usage: touch <file>...\n");
    exit();
  }
  for(i = 1; i < argc; i++){
    fd = open(argv[i], O_CREATE | O_WRONLY);     // no O_TRUNC: an existing file keeps its contents
    if(fd < 0)
      printf(2, "touch: cannot create %s\n", argv[i]);
    else
      close(fd);
  }
  exit();
}
