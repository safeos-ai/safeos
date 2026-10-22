#include "types.h"
#include "x86.h"
#include "defs.h"
#include "date.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"

int
sys_fork(void)
{
  return fork();
}

int
sys_exit(void)
{
  exit();
  return 0;  // not reached
}

int
sys_wait(void)
{
  return wait();
}

int
sys_kill(void)
{
  int pid;

  if(argint(0, &pid) < 0)
    return -1;
  return kill(pid);
}

int
sys_getpid(void)
{
  return myproc()->pid;
}

int
sys_sbrk(void)
{
  int addr;
  int n;

  if(argint(0, &n) < 0)
    return -1;
  addr = myproc()->sz;
  if(growproc(n) < 0)
    return -1;
  return addr;
}

int
sys_sleep(void)
{
  int n;
  uint ticks0;

  if(argint(0, &n) < 0)
    return -1;
  acquire(&tickslock);
  ticks0 = ticks;
  while(ticks - ticks0 < n){
    if(myproc()->killed){
      release(&tickslock);
      return -1;
    }
    sleep(&ticks, &tickslock);
  }
  release(&tickslock);
  return 0;
}

// return how many clock tick interrupts have occurred
// since start.
int
sys_uptime(void)
{
  uint xticks;

  acquire(&tickslock);
  xticks = ticks;
  release(&tickslock);
  return xticks;
}

/*int
sys_shutdown(void)
{
  // Send the ACPI shutdown signal to the system power port
  // 0x2000 is the standard ACPI power-off code for legacy x86 setups
  outw(0x604, 0x2000);
  
  return 0; // Will never be reached because the computer turns off
}*/
// Force a hardware reset via triple fault - portable across
// QEMU, VMware, and real hardware, since it relies on
// architectural CPU behavior rather than emulator-specific I/O ports.
int
sys_shutdown(void)
{
  // reboot
  /*
  volatile int i;
  outb(0xCF9, 0x06);          // PCI reset control: hard reset
  for(i = 0; i < 1000000; i++)
    ;
  outb(0xCF9, 0x0E);          // full reset, if the first write was ignored
  for(i = 0; i < 1000000; i++)
    ;
  */
  // shutdown
  volatile unsigned short idt[3] = {0, 0, 0};
  asm volatile("lidt (%0)" : : "r" (idt));   // last resort: triple fault
  asm volatile("int $3");
  return 0;
}
// Return the id of the CPU currently executing this syscall.
int
sys_getcpu(void)
{
  int id;
  pushcli();
  id = cpuid();
  popcli();
  return id;
}

// ---- reports: an installed app's own log, kept by the kernel (rootregistry.c) ----
extern int apps_report_write(char *text, int n);
extern int apps_report_read(char *buf, int max);
extern int apps_report_clear(void);

int
sys_write_report(void)
{
  char *text;
  int n;

  if(argint(1, &n) < 0 || n < 0 || argptr(0, &text, n) < 0)
    return -1;
  return apps_report_write(text, n);
}

int
sys_read_report(void)
{
  char *buf;
  int max;

  if(argint(1, &max) < 0 || max < 0 || argptr(0, &buf, max) < 0)
    return -1;
  return apps_report_read(buf, max);
}

int
sys_clear_report(void)
{
  return apps_report_clear();
}
