// SafeOS Owner-Mode: the one hook the kernel calls once the file system is up.
// forkret() calls root_fs_up() in the first process, after iinit() and initlog()
// and before that process can run any user code. Everything Owner-Mode needs from
// a working file system at boot goes here, so proc.c never has to change again.
#include "types.h"
#include "defs.h"
#include "rootowner.h"

void
root_fs_up(void)
{
  root_confirm();     // chain-boot: this kernel reached a working file system
  owner_fs_up();      // Owner: create and guard /owner, load the rules
}
