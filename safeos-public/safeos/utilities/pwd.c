// pwd: print the current directory. xv6 has no system call for it, so walk up through "..": at each level
// find the name of the current directory inside its parent, then chdir to the parent. The chdir changes
// only this process, not the shell that started it.
#include "types.h"
#include "stat.h"
#include "user.h"
#include "fs.h"

#define MAXDEPTH 16

static int
find_name(uint ino, char *out)       // the name of inode ino inside the parent directory (".."): 0, or -1
{
  int fd;
  struct dirent de;

  if((fd = open("..", 0)) < 0)
    return -1;
  while(read(fd, &de, sizeof(de)) == sizeof(de)){
    if(de.inum == 0 || de.inum != ino)
      continue;
    memmove(out, de.name, DIRSIZ);
    out[DIRSIZ] = 0;                 // a 14-character name has no terminator in the entry
    if(strcmp(out, ".") == 0 || strcmp(out, "..") == 0)
      continue;
    close(fd);
    return 0;
  }
  close(fd);
  return -1;
}

int
main(void)
{
  char names[MAXDEPTH][DIRSIZ + 1];
  struct stat here, up;
  int depth = 0, i;

  for(;;){
    if(stat(".", &here) < 0 || stat("..", &up) < 0)
      goto fail;
    if(here.ino == up.ino && here.dev == up.dev)
      break;                         // the root is its own parent
    if(depth >= MAXDEPTH || find_name(here.ino, names[depth]) < 0)
      goto fail;
    depth++;
    if(chdir("..") < 0)
      goto fail;
  }
  if(depth == 0)
    printf(1, "/");
  for(i = depth - 1; i >= 0; i--)
    printf(1, "/%s", names[i]);
  printf(1, "\n");
  exit();

fail:
  printf(2, "pwd: cannot read the directory\n");
  exit();
}
