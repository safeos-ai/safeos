// SafeOS Owner-Mode boot-time gate (first kernel only).
// Called as the first statement of main(): one CPU, interrupts off, paging is
// entrypgdir (low 4 MB identity-mapped), the boot GDT is still loaded, and no
// hardware has been set up yet. Returns only when this kernel should keep booting.
#include "types.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "elf.h"
#include "x86.h"
#include "rootblock.h"
#include "rootio.h"
#include "sha256.h"
#include "rootpass.h"

#define SECTSIZE     512
#define CHAIN_SECTOR 2048      // second kernel's first sector in xv6.img
#define TRAMP_ADDR   0x7000    // trampoline link and load address
#define TRAMP_MAX    0xB00     // keep clear of the boot sector at 0x7C00
#define ELF_SCRATCH  0x10000   // where the ELF header is read, as bootmain does
#define GATE_SPIN    4000000   // upper bound on any status-poll loop
#define POLLS_PER_SEC 20000000 // backstop only: the RTC ends a wait normally

#ifndef ROOT_WINDOW_SECS
#define ROOT_WINDOW_SECS 30    // window when an Owner passphrase is set
#endif
#ifndef ROOT_SETUP_SECS
#define ROOT_SETUP_SECS 60     // window when none is set yet
#endif

#define NOTICE_NONE    0
#define NOTICE_FIRST   1
#define NOTICE_DAMAGED 2
#define NOTICE_FAILED  3

extern uchar _binary_chain_start[], _binary_chain_size[];

// ---- disk: kernel image reads ----

static void
gate_waitdisk(void)
{
  while((inb(0x1F7) & 0xC0) != 0x40)
    ;
}

static void
gate_readsect(void *dst, uint sector)
{
  gate_waitdisk();
  outb(0x1F2, 1);
  outb(0x1F3, sector);
  outb(0x1F4, sector >> 8);
  outb(0x1F5, sector >> 16);
  outb(0x1F6, (sector >> 24) | 0xE0);
  outb(0x1F7, 0x20);
  gate_waitdisk();
  insl(0x1F0, dst, SECTSIZE/4);
}

// ---- disk: Owner block I/O, bounded polling, drive 0 ----

static void
gate_delay(void)                   // ~400 ns: let the status register settle after a command
{
  inb(0x3F6); inb(0x3F6); inb(0x3F6); inb(0x3F6);
}

static int
gate_wait_busy_clear(void)         // status byte, or -1 on timeout
{
  int i, st;

  for(i = 0; i < GATE_SPIN; i++){
    st = inb(0x1F7);
    if((st & 0x80) == 0)
      return st;
  }
  return -1;
}

static int
gate_wait_drq(void)                // 0 = data request raised, -1 = error or timeout
{
  int i, st;

  for(i = 0; i < GATE_SPIN; i++){
    st = inb(0x1F7);
    if(st & 0x21)                  // ERR or DF
      return -1;
    if((st & 0x88) == 0x08)        // not busy, DRQ
      return 0;
  }
  return -1;
}

static void
gate_select(void)
{
  outb(0x1F2, 1);
  outb(0x1F3, ROOT_SECTOR & 0xFF);
  outb(0x1F4, ROOT_SECTOR >> 8);
  outb(0x1F5, ROOT_SECTOR >> 16);
  outb(0x1F6, (ROOT_SECTOR >> 24) | 0xE0);
}

static int
gate_read_block(struct rootblock *rb)
{
  outb(0x3F6, 2);                  // nIEN: no disk interrupts while nothing can handle them
  if(gate_wait_busy_clear() < 0)
    return -1;
  gate_select();
  outb(0x1F7, 0x20);               // READ SECTORS
  gate_delay();
  if(gate_wait_drq() < 0)
    return -1;
  insl(0x1F0, rb, SECTSIZE/4);
  return 0;
}

static int
gate_write_block(struct rootblock *rb)
{
  int st;

  outb(0x3F6, 2);
  if(gate_wait_busy_clear() < 0)
    return -1;
  gate_select();
  outb(0x1F7, 0x30);               // WRITE SECTORS
  gate_delay();
  if(gate_wait_drq() < 0)
    return -1;
  outsl(0x1F0, rb, SECTSIZE/4);
  gate_delay();
  st = gate_wait_busy_clear();
  if(st < 0 || (st & 0x21))
    return -1;
  outb(0x1F7, 0xE7);               // FLUSH CACHE: best effort
  gate_delay();
  gate_wait_busy_clear();
  return 0;
}

// Write the block and read it back; 0 = verified.
static int
gate_save(struct rootblock *rb)
{
  struct rootblock chk;
  int ok = 0;

  if(gate_write_block(rb) == 0 && gate_read_block(&chk) == 0 &&
     rootblock_check(&chk) == ROOTBLOCK_OK && chk.chosen == rb->chosen &&
     chk.stage == rb->stage && chk.failures == rb->failures &&
     chk.passset == rb->passset)
    ok = 1;
  outb(0x3F8, ok ? 0x57 : 0x45);   // DEBUG: W = verified, E = failed
  return ok ? 0 : -1;
}

// ---- the second kernel ----

static int
gate_second_kernel_ok(void)
{
  struct elfhdr *elf = (struct elfhdr*)ELF_SCRATCH;
  struct proghdr *ph, *eph;
  int i;

  for(i = 0; i < 8; i++)
    gate_readsect((uchar*)elf + i*SECTSIZE, CHAIN_SECTOR + i);
  if(elf->magic != ELF_MAGIC)
    return 0;
  if(elf->phnum == 0 || elf->phnum > 8 ||
     elf->phoff + elf->phnum * sizeof(struct proghdr) > 4096)
    return 0;
  if(elf->entry < 0x100000 || elf->entry >= 4*1024*1024)
    return 0;
  ph = (struct proghdr*)((uchar*)elf + elf->phoff);
  eph = ph + elf->phnum;
  for(; ph < eph; ph++){
    if(ph->memsz == 0)
      continue;
    if(ph->filesz > ph->memsz || ph->paddr < 0x100000 ||
       ph->paddr + ph->memsz > 4*1024*1024)
      return 0;
  }
  if((uint)_binary_chain_size > TRAMP_MAX)
    return 0;
  return 1;
}

// ---- hash self-test: two standard vectors ("abc" and the 56-byte NIST string) ----

static int
sha_selftest(void)
{
  static const uchar abc_want[32] = {
    0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
    0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad };
  static const uchar two_want[32] = {
    0x24,0x8d,0x6a,0x61,0xd2,0x06,0x38,0xb8,0xe5,0xc0,0x26,0x93,0x0c,0x3e,0x60,0x39,
    0xa3,0x3c,0xe4,0x59,0x64,0xff,0x21,0x67,0xf6,0xec,0xed,0xd4,0x19,0xdb,0x06,0xc1 };
  uchar d[32];
  int i, bad = 0;

  sha256((const uchar*)"abc", 3, d);
  for(i = 0; i < 32; i++)
    if(d[i] != abc_want[i])
      bad |= 1;
  sha256((const uchar*)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, d);
  for(i = 0; i < 32; i++)
    if(d[i] != two_want[i])
      bad |= 2;
  return bad;
}

// ---- text helpers ----

static char*
kernel_name(uint k)
{
  return k == ROOT_KERNEL_SAFEOS ? "SafeOS" : "xv6";
}

static char*
stage_name(uint s)
{
  if(s == ROOT_STAGE_NONE)
    return "none";
  if(s == ROOT_STAGE_HANDOVER)
    return "handover";
  if(s == ROOT_STAGE_CONFIRMED)
    return "confirmed";
  return "?";
}

static void
put_num(uint n)
{
  char tmp[11];
  int i = 0;

  if(n == 0){
    root_putc('0');
    return;
  }
  while(n > 0 && i < 10){
    tmp[i++] = '0' + n % 10;
    n /= 10;
  }
  while(i > 0)
    root_putc(tmp[--i]);
}

// ---- the interaction window ----

static void
show_banner(struct rootblock *rb, int notice, int secs)
{
  root_puts("\n=== SafeOS Owner-Mode ===\n");
  if(notice == NOTICE_FIRST)
    root_puts("First boot: the Owner block was created.\n");
  else if(notice == NOTICE_DAMAGED)
    root_puts("The Owner block was damaged and has been reset; xv6 is chosen.\n");
  else if(notice == NOTICE_FAILED)
    root_puts("The last SafeOS boot did not finish; xv6 is chosen again.\n");
  root_puts("Chosen kernel: ");
  root_puts(kernel_name(rb->chosen));
  root_puts("\n");
  if(rb->passset){
    root_puts("Press any key within ");
    root_putint2(secs);
    root_puts(" seconds for the Owner menu.\n");
  } else {
    root_puts("No Owner passphrase is set. Press any key within ");
    root_putint2(secs);
    root_puts(" seconds to set one.\n");
  }
}

static void
show_left(int left)
{
  root_puts("\rTime left: ");
  root_putint2(left);
  root_puts(" s ");
}

// Wait about 'secs' seconds, timed by RTC second changes. Returns 1 if a key was
// pressed (only when watch_keys is set), 0 on timeout. The first second can be
// shorter, because counting starts at the next RTC tick.
static int
wait_seconds(int secs, int watch_keys, int show)
{
  uint polls, cap;
  int s, last, left;

  if(secs <= 0)
    return 0;
  cap = (uint)secs * POLLS_PER_SEC;
  last = root_rtc_seconds();
  left = secs;
  if(show)
    show_left(left);
  for(polls = 0; polls < cap; polls++){
    if(watch_keys && root_getkey() > 0)
      return 1;
    s = root_rtc_seconds();
    if(s < 0 || s == last)
      continue;
    last = s;
    if(--left <= 0)
      return 0;
    if(show)
      show_left(left);
  }
  return 0;
}

static void
gate_leave(void)                   // leave the screen clean for the kernel that boots next
{
  root_drain();
  root_puts("\n");
  root_clear();
}

// ---- the Owner: setup, login, menu ----

static void
choose_kernel(struct rootblock *rb, int sk_ok)
{
  char line[8];
  int n;

  root_puts("Default kernel: 1) xv6");
  if(sk_ok)
    root_puts("   2) SafeOS");
  root_puts("   (Enter keeps ");
  root_puts(kernel_name(rb->chosen));
  root_puts("): ");
  n = root_readline(line, sizeof(line), 0, 60);
  if(n > 0 && line[0] == '1')
    rb->chosen = ROOT_KERNEL_XV6;
  else if(n > 0 && line[0] == '2' && sk_ok)
    rb->chosen = ROOT_KERNEL_SAFEOS;
}

// Set or change the Owner passphrase (and, with ask_kernel, the default kernel).
// Returns 0 if it was saved.
static int
owner_setup(struct rootblock *rb, int ask_kernel, int sk_ok)
{
  char p1[ROOT_PASS_MAX + 1], p2[ROOT_PASS_MAX + 1];
  uchar ent[16], h[32], salt[16];
  uint e;
  int tries, n1 = 0, n2, i, ok = 0;

  for(tries = 0; tries < 3 && !ok; tries++){
    root_puts("New Owner passphrase (1 to 64 characters): ");
    n1 = root_readline(p1, sizeof(p1), 1, 60);
    if(n1 < 0){
      root_puts("Timed out.\n");
      break;
    }
    if(n1 == 0){
      root_puts("An empty passphrase is not accepted.\n");
      continue;
    }
    root_puts("Again: ");
    n2 = root_readline(p2, sizeof(p2), 1, 60);
    if(n2 < 0){
      root_puts("Timed out.\n");
      break;
    }
    if(n1 != n2 || memcmp(p1, p2, n1) != 0){
      root_puts("The two entries differ.\n");
      continue;
    }
    ok = 1;
  }
  if(ok){
    for(i = 0; i < 4; i++){
      e = root_entropy();
      ent[4*i]   = e;
      ent[4*i+1] = e >> 8;
      ent[4*i+2] = e >> 16;
      ent[4*i+3] = e >> 24;
    }
    sha256(ent, 16, h);
    for(i = 0; i < 16; i++)
      salt[i] = h[i];
    root_pass_set(rb, salt, p1, n1);
    if(ask_kernel)
      choose_kernel(rb, sk_ok);
    rootblock_seal(rb);
    if(gate_save(rb) == 0){
      root_puts("Owner passphrase saved.\n");
    } else {
      root_puts("Could not write the Owner block; nothing was saved.\n");
      ok = 0;
    }
  }
  for(i = 0; i <= ROOT_PASS_MAX; i++)
    p1[i] = p2[i] = 0;
  return ok ? 0 : -1;
}

static int
owner_login(struct rootblock *rb)
{
  char p[ROOT_PASS_MAX + 1];
  int tries, n, i, ok = 0;

  for(tries = 0; tries < 3 && !ok; tries++){
    root_puts("Owner passphrase: ");
    n = root_readline(p, sizeof(p), 1, 30);
    if(n < 0){
      root_puts("Timed out.\n");
      break;
    }
    if(root_pass_verify(rb, p, n))
      ok = 1;
    else
      root_puts("Wrong passphrase.\n");
  }
  for(i = 0; i <= ROOT_PASS_MAX; i++)
    p[i] = 0;
  return ok;
}

static void
owner_save(struct rootblock *rb)
{
  rootblock_seal(rb);
  if(gate_save(rb) == 0)
    root_puts("Saved.\n");
  else
    root_puts("Could not write the Owner block.\n");
}

static void
owner_menu(struct rootblock *rb, int sk_ok)
{
  char line[8];
  int n;

  for(;;){
    root_puts("\n--- Owner menu ---\n");
    root_puts("Chosen kernel: ");
    root_puts(kernel_name(rb->chosen));
    root_puts("\nLast hand-over stage: ");
    root_puts(stage_name(rb->stage));
    root_puts("\nFailed trials: ");
    put_num(rb->failures);
    root_puts("\nSafeOS kernel found: ");
    root_puts(sk_ok ? "yes" : "no");
    root_puts("\n1) boot xv6   2) boot SafeOS   3) change passphrase\n");
    root_puts("4) clear failure count   Enter) boot the chosen kernel\n> ");
    n = root_readline(line, sizeof(line), 0, 60);
    if(n <= 0)
      return;
    if(line[0] == '1'){
      rb->chosen = ROOT_KERNEL_XV6;
      owner_save(rb);
      return;                    // a kernel choice boots it right away
    } else if(line[0] == '2'){
      if(!sk_ok){
        root_puts("No valid SafeOS kernel in the image.\n");
      } else {
        rb->chosen = ROOT_KERNEL_SAFEOS;
        owner_save(rb);
        return;                    // a kernel choice boots it right away
      }
    } else if(line[0] == '3'){
      owner_setup(rb, 0, sk_ok);
    } else if(line[0] == '4'){
      rb->failures = 0;
      owner_save(rb);
    }
  }
}

void
root_chainload(void)
{
  struct rootblock rb;
  int state, notice = NOTICE_NONE, key, sk_ok, hash_ok, secs;

  root_io_init();
  outb(0x3F8, 'G');                // DEBUG: gate reached
  hash_ok = (sha_selftest() == 0);
  outb(0x3F8, hash_ok ? 'h' : 'H'); // DEBUG: h = hash self-test passed

  // 1. Read the Owner block, repairing it if needed.
  if(gate_read_block(&rb) < 0)
    return;                        // disk not usable: boot this kernel, change nothing
  sk_ok = gate_second_kernel_ok();
  state = rootblock_check(&rb);
  if(state == ROOTBLOCK_BLANK){
    outb(0x3F8, 'b');              // DEBUG: first boot after a build
    notice = NOTICE_FIRST;
    rootblock_init(&rb, sk_ok ? ROOT_KERNEL_SAFEOS : ROOT_KERNEL_XV6);
    if(gate_save(&rb) < 0)
      return;
  } else if(state == ROOTBLOCK_DAMAGED){
    outb(0x3F8, 'd');              // DEBUG: damaged block, fail safe
    notice = NOTICE_DAMAGED;
    rootblock_init(&rb, ROOT_KERNEL_XV6);
    rb.failures = 1;
    rootblock_seal(&rb);
    gate_save(&rb);
  }
  if(rb.stage == ROOT_STAGE_HANDOVER){
    outb(0x3F8, 'f');              // DEBUG: the last hand-over never confirmed
    notice = NOTICE_FAILED;
    rb.stage = ROOT_STAGE_NONE;
    rb.chosen = ROOT_KERNEL_XV6;
    rb.failures++;
    rootblock_seal(&rb);
    gate_save(&rb);
  }

  // 2. The Owner window.
  if(!hash_ok){
    root_puts("Owner passphrase unavailable: the SHA-256 self-test failed.\n");
  } else {
    secs = rb.passset ? ROOT_WINDOW_SECS : ROOT_SETUP_SECS;
    if(secs > 0){
      show_banner(&rb, notice, secs);
      root_drain();                // keys pressed during the BIOS must not count
      key = wait_seconds(secs, 1, 1);
      if(key){
        root_drain();
        root_puts("\n");
        if(rb.passset){
          if(owner_login(&rb))
            owner_menu(&rb, sk_ok);
          else
            root_puts("Access denied. Booting the chosen kernel.\n");
        } else {
          owner_setup(&rb, 1, sk_ok);
        }
        wait_seconds(2, 0, 0);
      }
    }
  }

  // 3. Decide.
  if(rb.chosen != ROOT_KERNEL_SAFEOS){
    outb(0x3F8, 'x');              // DEBUG: xv6 is the chosen kernel
    gate_leave();
    return;
  }
  if(!sk_ok){
    root_puts("\nNo valid SafeOS kernel found; booting xv6.\n");
    wait_seconds(2, 0, 0);
    gate_leave();
    return;
  }
  outb(0x3F8, 'L');                // DEBUG: second kernel looks valid

  // 4. Put stage 1 on disk, verified, before the point of no return.
  rb.stage = ROOT_STAGE_HANDOVER;
  rootblock_seal(&rb);
  if(gate_save(&rb) < 0){
    root_puts("\nCould not record the hand-over; booting xv6.\n");
    wait_seconds(2, 0, 0);
    gate_leave();
    return;
  }
  outb(0x3F8, 'w');                // DEBUG: stage 1 is on disk

  gate_leave();
  memmove((void*)TRAMP_ADDR, _binary_chain_start, (uint)_binary_chain_size);
  ((void(*)(void))TRAMP_ADDR)();   // does not return
}
