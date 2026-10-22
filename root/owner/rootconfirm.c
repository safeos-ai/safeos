// Owner-Mode confirm point, for kernels that can be handed over to.
// Called once by the first process, after the file system is up: clears the
// trial flag, telling the gate that this kernel booted.
#include "types.h"
#include "defs.h"
#include "param.h"
#include "spinlock.h"
#include "sleeplock.h"
#include "fs.h"
#include "buf.h"
#include "rootblock.h"

#if ROOT_SECTOR >= FSSIZE
#error "ROOT_SECTOR must be below FSSIZE: the buffer cache driver rejects larger block numbers"
#endif

void
root_confirm(void)
{
  struct buf *b;
  struct rootblock *rb;

  b = bread(0, ROOT_SECTOR);       // device 0 = the boot disk
  rb = (struct rootblock*)b->data;
  if(rootblock_check(rb) == ROOTBLOCK_OK && rb->stage == ROOT_STAGE_HANDOVER){
    rb->stage = ROOT_STAGE_CONFIRMED;
    rootblock_seal(rb);
    bwrite(b);
  }
  brelse(b);
}
