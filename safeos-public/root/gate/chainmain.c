// Trampoline: runs at physical 0x7000 with paging off. Loads the second kernel
// (an ELF image starting at sector CHAIN_SECTOR) and jumps to its entry point.
// Freestanding: no string literals and no globals, because only .text is embedded.
#include "types.h"
#include "elf.h"
#include "x86.h"

#define SECTSIZE     512
#define CHAIN_SECTOR 2048

static void
waitdisk(void)
{
  while((inb(0x1F7) & 0xC0) != 0x40)
    ;
}

static void
readsect(void *dst, uint sector)
{
  waitdisk();
  outb(0x1F2, 1);
  outb(0x1F3, sector);
  outb(0x1F4, sector >> 8);
  outb(0x1F5, sector >> 16);
  outb(0x1F6, (sector >> 24) | 0xE0);
  outb(0x1F7, 0x20);
  waitdisk();
  insl(0x1F0, dst, SECTSIZE/4);
}

static void
readseg(uchar *pa, uint count, uint offset)
{
  uchar *epa = pa + count;

  pa -= offset % SECTSIZE;
  offset = (offset / SECTSIZE) + CHAIN_SECTOR;
  for(; pa < epa; pa += SECTSIZE, offset++)
    readsect(pa, offset);
}

void
chainmain(void)
{
  struct elfhdr *elf = (struct elfhdr*)0x10000;
  struct proghdr *ph, *eph;
  void (*entry)(void);
  uchar *pa;

  outb(0x3F8, 'T');                  // DEBUG: trampoline running
  readseg((uchar*)elf, 4096, 0);
  if(elf->magic != ELF_MAGIC)
    for(;;)
      ;
  ph = (struct proghdr*)((uchar*)elf + elf->phoff);
  eph = ph + elf->phnum;
  for(; ph < eph; ph++){
    if(ph->memsz == 0)
      continue;
    pa = (uchar*)ph->paddr;
    readseg(pa, ph->filesz, ph->off);
    if(ph->memsz > ph->filesz)
      stosb(pa + ph->filesz, 0, ph->memsz - ph->filesz);
  }
  outb(0x3F8, 'J');                  // DEBUG: jumping to the new kernel
  entry = (void(*)(void))(elf->entry);
  entry();
}
