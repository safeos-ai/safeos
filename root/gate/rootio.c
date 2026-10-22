// SafeOS Owner-Mode boot-time I/O. See rootio.h.
#include "types.h"
#include "x86.h"
#include "rootio.h"

#define COM1      0x3F8
#define VGA_BASE  ((volatile ushort*)0xB8000)   // inside the 4 MB identity map of entrypgdir
#define VGA_COLS  80
#define VGA_ROWS  25
#define ROOTIO_POLLS_PER_SEC 20000000   // backstop only: the RTC ends the wait normally

int kbdgetc(void);             // kbd.c; not declared in defs.h

static int com1_present;
static int vga_row, vga_col;
static uint mixpool = 0x9e3779b9;

static void
vga_cursor(void)
{
  int pos = vga_row * VGA_COLS + vga_col;

  outb(0x3D4, 14);
  outb(0x3D5, pos >> 8);
  outb(0x3D4, 15);
  outb(0x3D5, pos);
}

static void
vga_clear(void)
{
  int i;

  for(i = 0; i < VGA_COLS * VGA_ROWS; i++)
    VGA_BASE[i] = 0x0720;      // space, light grey on black
  vga_row = vga_col = 0;
  vga_cursor();
}

static void
serial_putc(int c)
{
  int i;

  if(!com1_present)
    return;
  for(i = 0; i < 20000 && !(inb(COM1+5) & 0x20); i++)
    ;
  outb(COM1, c);
}

void
root_io_init(void)
{
  // Same settings as uartinit(), but no interrupts: the kernel enables those later.
  outb(COM1+2, 0);
  outb(COM1+3, 0x80);
  outb(COM1+0, 12);            // 115200 / 9600
  outb(COM1+1, 0);
  outb(COM1+3, 0x03);
  outb(COM1+4, 0);
  outb(COM1+1, 0);
  com1_present = (inb(COM1+5) != 0xFF);   // 0xFF = no serial port
  vga_clear();
}

void
root_clear(void)
{
  vga_clear();
}

void
root_putc(int c)
{
  if(c == '\n'){
    serial_putc('\r');
    serial_putc('\n');
    vga_col = 0;
    vga_row++;
  } else if(c == '\r'){
    serial_putc('\r');
    vga_col = 0;
  } else if(c == '\b'){
    serial_putc('\b');
    if(vga_col > 0)
      vga_col--;
  } else {
    serial_putc(c);
    VGA_BASE[vga_row * VGA_COLS + vga_col] = (c & 0xFF) | 0x0700;
    if(++vga_col >= VGA_COLS){
      vga_col = 0;
      vga_row++;
    }
  }
  if(vga_row >= VGA_ROWS)
    vga_clear();
  else
    vga_cursor();
}

void
root_puts(char *s)
{
  for(; *s; s++)
    root_putc(*s);
}

void
root_putint2(int n)
{
  root_putc(n >= 10 ? '0' + (n / 10) % 10 : ' ');
  root_putc('0' + n % 10);
}

int
root_getkey(void)
{
  int st, c;

  if(com1_present && (inb(COM1+5) & 0x01)){
    c = inb(COM1);
    return c ? c : -1;
  }
  st = inb(0x64);
  if(st & 0x01){
    if(st & 0x20){             // byte from the mouse port (or a floating bus): discard
      inb(0x60);
      return -1;
    }
    c = kbdgetc();
    if(c > 0)
      return c;
  }
  return -1;
}

void
root_drain(void)
{
  int i;

  for(i = 0; i < 64 && (inb(0x64) & 0x01); i++)
    inb(0x60);
  if(com1_present)
    for(i = 0; i < 64 && (inb(COM1+5) & 0x01); i++)
      inb(COM1);
}

static int
rtc_read(int reg)
{
  outb(0x70, reg);
  return inb(0x71);
}

int
root_rtc_seconds(void)
{
  int i;

  for(i = 0; i < 100000; i++)
    if(!(rtc_read(0x0A) & 0x80))   // update-in-progress clear
      return rtc_read(0x00);
  return -1;
}

static uint
rdtsc_lo(void)
{
  uint lo, hi;

  asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
  return lo;
}

uint
root_entropy(void)
{
  uint v = rdtsc_lo();

  mixpool = ((mixpool << 5) | (mixpool >> 27)) ^ v ^
            ((uint)rtc_read(0x00) << 8) ^ ((uint)rtc_read(0x02) << 16);
  return mixpool;
}

// Read one line. mask: show '*' instead of the typed characters.
// Returns the length, or -1 if no key arrived for idle_secs seconds.
int
root_readline(char *buf, int max, int mask, int idle_secs)
{
  int n = 0, c, s, last, left;
  uint polls = 0, cap = (uint)idle_secs * ROOTIO_POLLS_PER_SEC;

  last = root_rtc_seconds();
  left = idle_secs;
  for(;;){
    c = root_getkey();
    if(c > 0){
      root_entropy();            // the timing of a person's keystrokes feeds the salt
      left = idle_secs;
      polls = 0;
      if(c == '\r' || c == '\n'){
        buf[n] = 0;
        root_putc('\n');
        return n;
      }
      if(c == '\b' || c == 0x7F){
        if(n > 0){
          n--;
          root_putc('\b');
          root_putc(' ');
          root_putc('\b');
        }
      } else if(c >= 32 && c < 127 && n < max - 1){
        buf[n++] = c;
        root_putc(mask ? '*' : c);
      }
      continue;
    }
    if(++polls >= cap)
      return -1;
    s = root_rtc_seconds();
    if(s < 0 || s == last)
      continue;
    last = s;
    if(--left <= 0)
      return -1;
  }
}
