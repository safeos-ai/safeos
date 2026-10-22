// SafeOS Owner guard: programs cannot reach the /owner directory.
// The directory is identified by inode number, found once at boot, so every
// route to it through namex() hits the same check.
#include "types.h"
#include "defs.h"
#include "param.h"
#include "stat.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"
#include "spinlock.h"
#include "sleeplock.h"
#include "fs.h"
#include "file.h"
#include "rootowner.h"

extern struct inode *create(char *path, short type, short major, short minor);   // sysfile.c

uint owner_dir_inum;     // set once at boot, before any program runs; 0 = guard off
volatile int owner_fs_ready;   // 1 once /owner and the rules file are set up

#ifdef APPS_OPEN
#define APPS_PROTECT 0               // make APPS_OPEN=1: /apps and /bin are open, so the tamper tests can run
#else
#define APPS_PROTECT 1
#endif

static int
caller_is_owner(void)
{
  struct proc *p = myproc();

  return p == 0 || p->kproc;   // no process (early boot) or the Owner
}

// namex() found this inode by name. 1 = the caller must not see it.
int
owner_guard_denies(struct inode *ip)
{
  if(owner_dir_inum == 0 || ip->dev != ROOTDEV)
    return 0;
  if(ip->inum == owner_dir_inum)
    return !caller_is_owner();
  if(APPS_PROTECT && apps_report_hidden(ip->inum))   // an app's report directory and file: its own group and the Owner only
    return !caller_is_owner();
  return 0;
}

// nameiparent() is about to return 'parent' for the final element 'name'.
// 1 = refuse, so programs cannot create, remove or link the name "owner" in the root.
int
owner_guard_denies_name(struct inode *parent, char *name)
{
  if(owner_dir_inum == 0 || parent->dev != ROOTDEV || caller_is_owner())
    return 0;
  if(parent->inum == ROOTINO && namecmp(name, "owner") == 0)
    return 1;
  if(!APPS_PROTECT)
    return 0;
  if(parent->inum == ROOTINO && namecmp(name, "apps") == 0)
    return 1;                         // /apps cannot be removed or made again
  if(parent->inum == ROOTINO && (namecmp(name, "bin") == 0 || namecmp(name, "init") == 0 || namecmp(name, "sh") == 0))
    return 1;                         // /bin, /init and /sh are what the system boots from: not removed, made again or linked
  if(bin_guard_dir(parent->inum))
    return 1;                         // nothing is made, removed or linked inside /bin
  return apps_guard_has(parent->inum);   // nothing is made, removed or linked inside /apps or an installed app's directory
}

// An installed app's files cannot be opened for writing, whatever name they are reached by.
int
apps_guard_denies_write(struct inode *ip)
{
  if(!APPS_PROTECT || owner_dir_inum == 0 || ip->dev != ROOTDEV || caller_is_owner())
    return 0;
  return apps_guard_has(ip->inum) || bin_guard_has(ip->inum);   // an installed app's files, everything in /bin, and /init
}

// ...and they cannot be given a second name.
int
apps_guard_denies_link(struct inode *ip)
{
  if(!APPS_PROTECT || owner_dir_inum == 0 || ip->dev != ROOTDEV || caller_is_owner())
    return 0;
  return apps_guard_has(ip->inum) || apps_report_is(ip->inum) || bin_guard_has(ip->inum);   // sealed files, report files, /bin and /init get no second name
}

// Called once, from forkret, right after the file system comes up and before any
// program runs: create /owner if it is missing, then switch the guard on.
void
owner_fs_up(void)
{
  struct inode *ip;
  uint inum;
  int isdir;

  begin_op();
  ip = namei("/owner");
  if(ip == 0){
    ip = create("/owner", T_DIR, 0, 0);     // returned locked
    if(ip == 0){
      end_op();
      cprintf("[Owner] cannot create /owner: the guard is OFF\n");
      return;
    }
    inum = ip->inum;
    isdir = 1;
    iunlockput(ip);
  } else {
    ilock(ip);
    inum = ip->inum;
    isdir = (ip->type == T_DIR);
    iunlockput(ip);
  }
  end_op();
  if(!isdir){
    cprintf("[Owner] /owner exists but is not a directory: the guard is OFF\n");
    return;
  }
  owner_rules_boot();      // load /owner/rules while the guard is still off
  registry_apps_boot();      // installed apps: load /owner/apps, apply their rules, remove leftovers in /apps
  bin_guard_boot();        // seal /bin and /init: note their inodes, while the guard is still off
  owner_dir_inum = inum;
  owner_fs_ready = 1;
}
