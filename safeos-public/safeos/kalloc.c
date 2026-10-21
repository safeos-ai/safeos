// Physical memory allocator, intended to allocate
// memory for user processes, kernel stacks, page table pages,
// and pipe buffers. Allocates 4096-byte pages.
//
// SafeOS: physical memory is divided into pools. Each pool covers its own
// physical address range and has its own lock.
//   POOL_KERNEL  [0, 32 MB)        kalloc()           stacks, page tables, pipes
//   POOL_ROOT    [32 MB, 64 MB)    root_alloc_page()  Owner-only memory
//   POOL_USER    [64 MB, PHYSTOP)  kalloc_user()      pages mapped into user space
// kfree() finds the pool from the page's address, so its callers don't change.
// The Owner pool is left out of ordinary page tables (see vm.c), so nothing may be
// written into one of its pages from here: it has no free list, only a bitmap
// that lives in kernel memory.

#include "types.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "spinlock.h"
#include "mempool.h"

void freerange(void *vstart, void *vend);
extern char end[]; // first address after kernel loaded from ELF file
                   // defined by the kernel linker script in kernel.ld

struct run {
  struct run *next;
};

struct pool {
  struct spinlock lock;
  struct run *freelist;
  int nfree;
  int ntotal;             // pages added to this pool at boot
  char *name;
  uint lo;                // physical range [lo, hi)
  uint hi;
};

static struct pool pools[NPOOL] = {
  [POOL_KERNEL] = { .name = "kernel", .lo = 0,            .hi = KERNPOOL_TOP },
  [POOL_USER]   = { .name = "user",   .lo = ROOTPOOL_TOP, .hi = PHYSTOP },
  [POOL_ROOT]   = { .name = "owner",   .lo = KERNPOOL_TOP, .hi = ROOTPOOL_TOP },
};

static int use_lock;     // 0 until kinit2: early boot is single-CPU, no locks

// Owner pool: one bit per page, 1 = in use. Protected by pools[POOL_ROOT].lock.
#define ROOTPOOL_PAGES (ROOTPOOL_SIZE / PGSIZE)
static uchar rootmap[ROOTPOOL_PAGES / 8];

static struct pool*
pool_of(uint pa)
{
  int i;

  for(i = 0; i < NPOOL; i++)
    if(pa >= pools[i].lo && pa < pools[i].hi)
      return &pools[i];
  return 0;
}

// Initialization happens in two phases.
// 1. main() calls kinit1() while still using entrypgdir to place just
// the pages mapped by entrypgdir on free list.
// 2. main() calls kinit2() with the rest of the physical pages
// after installing a full page table that maps them on all cores.
void
kinit1(void *vstart, void *vend)
{
  int i;

  for(i = 0; i < NPOOL; i++)
    initlock(&pools[i].lock, pools[i].name);
  use_lock = 0;
  freerange(vstart, vend);
}

void
kinit2(void *vstart, void *vend)
{
  int i;

  freerange(vstart, vend);
  use_lock = 1;
  for(i = 0; i < NPOOL; i++)
    cprintf("pool %s: %d pages, physical %x-%x\n",
            pools[i].name, pools[i].nfree, pools[i].lo, pools[i].hi);
}

void
freerange(void *vstart, void *vend)
{
  char *p;
  struct pool *pl;

  p = (char*)PGROUNDUP((uint)vstart);
  for(; p + PGSIZE <= (char*)vend; p += PGSIZE){
    pl = pool_of(V2P(p));
    if(pl == &pools[POOL_ROOT]){   // never touched here: no kernel page table maps it
      pl->ntotal++;
      pl->nfree++;
      continue;
    }
    if(pl)
      pl->ntotal++;
    kfree(p);
  }
}
//PAGEBREAK: 21
// Free the page of physical memory pointed at by v,
// which normally should have been returned by a
// call to kalloc().  (The exception is when
// initializing the allocator; see kinit above.)
void
kfree(char *v)
{
  struct run *r;
  struct pool *pl;

  if((uint)v % PGSIZE || v < end || V2P(v) >= PHYSTOP)
    panic("kfree");
  pl = pool_of(V2P(v));
  if(pl == 0)
    panic("kfree: no pool");
  if(pl == &pools[POOL_ROOT])
    panic("kfree: owner pool page");

  // Fill with junk to catch dangling refs.
  memset(v, 1, PGSIZE);

  if(use_lock)
    acquire(&pl->lock);
  r = (struct run*)v;
  r->next = pl->freelist;
  pl->freelist = r;
  pl->nfree++;
  if(use_lock)
    release(&pl->lock);
}

static char*
pool_alloc(struct pool *pl)
{
  struct run *r;

  if(use_lock)
    acquire(&pl->lock);
  r = pl->freelist;
  if(r){
    pl->freelist = r->next;
    pl->nfree--;
  }
  if(use_lock)
    release(&pl->lock);
  return (char*)r;
}

// Allocate one 4096-byte page of physical memory from the kernel pool.
// Returns a pointer that the kernel can use.
// Returns 0 if the memory cannot be allocated.
char*
kalloc(void)
{
  return pool_alloc(&pools[POOL_KERNEL]);
}

// Same, from the user pool: for pages that will be mapped with PTE_U.
char*
kalloc_user(void)
{
  return pool_alloc(&pools[POOL_USER]);
}

int
phys_in_pool(int which, uint pa)
{
  return pa >= pools[which].lo && pa < pools[which].hi;
}

// Report occupancy of pool 'which' for ps. Returns -1 past the last pool.
// The pool lock is held only while copying two numbers, never while writing
// to the caller's buffers.
int
pool_info(int which, char *name, int namelen, int *nfree, int *ntotal)
{
  struct pool *pl;
  int f, t;

  if(which < 0 || which >= NPOOL)
    return -1;
  pl = &pools[which];
  acquire(&pl->lock);
  f = pl->nfree;
  t = pl->ntotal;
  release(&pl->lock);
  safestrcpy(name, pl->name, namelen);
  *nfree = f;
  *ntotal = t;
  return 0;
}

// Take one page of the Owner pool and return its physical address. This only
// marks the bit; the caller zeroes and uses the page, which only the Owner's
// page table maps.
int
root_alloc_page(uint *pa)
{
  struct pool *pl = &pools[POOL_ROOT];
  int i;

  acquire(&pl->lock);
  for(i = 0; i < ROOTPOOL_PAGES; i++){
    if(!(rootmap[i/8] & (1 << (i%8)))){
      rootmap[i/8] |= 1 << (i%8);
      pl->nfree--;
      release(&pl->lock);
      *pa = pl->lo + i * PGSIZE;
      return 0;
    }
  }
  release(&pl->lock);
  return -1;
}

void
root_free_page(uint pa)
{
  struct pool *pl = &pools[POOL_ROOT];
  int i;

  if(pa % PGSIZE || pa < pl->lo || pa >= pl->hi)
    panic("root_free_page");
  i = (pa - pl->lo) / PGSIZE;
  acquire(&pl->lock);
  if(!(rootmap[i/8] & (1 << (i%8))))
    panic("root_free_page: not allocated");
  rootmap[i/8] &= ~(1 << (i%8));
  pl->nfree++;
  release(&pl->lock);
}

// 1 if the Owner pool page at physical address pa is allocated (for the Ring 1 dispatcher).
int
root_page_is_allocated(uint pa)
{
  struct pool *pl = &pools[POOL_ROOT];
  int i, r;

  if(pa % PGSIZE || pa < pl->lo || pa >= pl->hi)
    return 0;
  i = (pa - pl->lo) / PGSIZE;
  acquire(&pl->lock);
  r = (rootmap[i/8] & (1 << (i%8))) != 0;
  release(&pl->lock);
  return r;
}
