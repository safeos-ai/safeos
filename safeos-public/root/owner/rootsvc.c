// Kernel side of the Owner's interface (see rootsvc.h). Everything here may use any
// kernel facility; rootowner.c may not.
#include "types.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "x86.h"
#include "proc.h"
#include "spinlock.h"
#include "sleeplock.h"
#include "fs.h"
#include "buf.h"
#include "rootblock.h"
#include "mempool.h"
#include "rootowner.h"
#include "rootsvc.h"

volatile int owner_chord;               // set by the keyboard path (kbd.c)

static struct spinlock ownerlock;
static volatile int owner_requested;    // protected by ownerlock; the Owner sleeps on its address

void
owner_init(void)
{
  initlock(&ownerlock, "owner");
  owner1_proc_create();       // the Owner is a Ring 1 process
}

// Called from consoleintr after cons.lock is released.
void
owner_request(void)
{
  acquire(&ownerlock);
  owner_requested = 1;
  wakeup((void*)&owner_requested);
  release(&ownerlock);
}

void
owner_wait_request(void)
{
  acquire(&ownerlock);
  while(!owner_requested)
    sleep((void*)&owner_requested, &ownerlock);
  owner_requested = 0;
  release(&ownerlock);
}

void
owner_clear_requests(void)
{
  acquire(&ownerlock);
  owner_requested = 0;
  release(&ownerlock);
}

int
owner_rtc_seconds(void)          // RTC seconds register (raw), or -1
{
  int i, v = -1;

  pushcli();
  for(i = 0; i < 1000; i++){
    outb(0x70, 0x0A);
    if(!(inb(0x71) & 0x80)){
      outb(0x70, 0x00);
      v = inb(0x71);
      break;
    }
  }
  popcli();
  return v;
}

void
owner_read_block(void *dst)
{
  struct buf *b;

  b = bread(0, ROOT_SECTOR);     // device 0 = the boot disk
  memmove(dst, b->data, sizeof(struct rootblock));
  brelse(b);
}

// Owner pool pages: only the Owner may take them.
