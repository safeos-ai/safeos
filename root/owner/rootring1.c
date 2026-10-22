// The Owner at Ring 1, kernel side: the dispatcher for gate 65 (step 3b-i).
// Every pointer from the Owner is checked before the kernel touches it.
#include "types.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "x86.h"
#include "proc.h"
#include "spinlock.h"
#include "mempool.h"
#include "psinfo.h"
#include "rootowner.h"
#include "rootsvc.h"

#define SVC_PRINT      1
#define SVC_WAIT       2
#define SVC_CLOSE      3
#define SVC_PUTC       4
#define SVC_GETC       5
#define SVC_RTC        6
#define SVC_PAGE_ALLOC 7
#define SVC_PAGE_FREE  8
#define SVC_READ_BLOCK 9
#define SVC_EXPOSURE   10
#define SVC_SNAPSHOT   11
#define SVC_KILL       12
#define SVC_GETPID     13
#define SVC_BUSY        14
#define SVC_RULE_SET    15
#define SVC_RULE_REMOVE 16
#define SVC_RULES_STATE 17
#define SVC_RULES_SAVE  18
#define SVC_KILLGROUP   19
#define SVC_KINDRULE_SET 20
#define SVC_REG_MODE    21
#define SVC_REG_ENTRY   22
#define SVC_INST_READ   23
#define SVC_INST_COMMIT 24
#define SVC_UNINST      25
#define SVC_REPORT_READ 26

#define MAX_PRINT       255
#define OWNER1_POOL_END (OWNER1_POOL_BASE + ROOTPOOL_SIZE)

// Is [addr, addr+len) wholly inside memory the Owner has mapped? Its image (with its
// zeroed data) is [0, p->sz), its stack is [OWNER1_STACK_LO, OWNER1_STACK_TOP), and the
// Owner pool is [OWNER1_POOL_BASE, OWNER1_POOL_END). Every page there exists.
static int
owner1_range_ok(struct proc *p, uint addr, uint len)
{
  uint end;

  if(len == 0)
    return 1;
  end = addr + len;
  if(end < addr)                    // wraparound
    return 0;
  if(end <= p->sz)
    return 1;
  if(addr >= OWNER1_STACK_LO && end <= OWNER1_STACK_TOP)
    return 1;
  if(addr >= OWNER1_POOL_BASE && end <= OWNER1_POOL_END)
    return 1;
  return 0;
}

// Called from trap() for vector 65. The hardware lets only CPL 0 and 1 reach it, and
// this checks again that the caller is the Owner. A bad call returns -1; the Owner is never killed.
void
owner_gate(struct trapframe *tf)
{
  struct proc *p = myproc();
  char buf[MAX_PRINT + 1];
  struct rule_req rq;
  struct kind_req kreq;
  struct reg_view rv;
  struct inst_req irq;
  struct uninst_req urq;
  char nm[16];
  uint a, b, pa;
  int r = -1, total;

  if(p == 0)
    panic("owner_gate: no process");
  if(p->kproc != 2 || (tf->cs & 3) != DPL_OWNER)
    panic("owner_gate: not from the Owner");

  a = tf->ebx;
  b = tf->ecx;
  switch(tf->eax){
  case SVC_PRINT:
    if(b <= MAX_PRINT && owner1_range_ok(p, a, b)){
      memmove(buf, (char*)a, b);        // safe: the kernel runs on the Owner's page table here
      buf[b] = 0;
      cprintf("%s", buf);
      r = 0;
    }
    break;
  case SVC_WAIT:
    owner_wait_request();
    r = 0;
    break;
  case SVC_CLOSE:
    owner_clear_requests();
    owner_console_close();
    r = 0;
    break;
  case SVC_PUTC:
    owner_putc(a & 0xff);
    r = 0;
    break;
  case SVC_GETC:
    r = owner_console_getc();           // a key, or -1 after about one timer tick
    break;
  case SVC_RTC:
    r = owner_rtc_seconds();
    break;
  case SVC_PAGE_ALLOC:
    r = 0;                              // 0 = none free
    if(root_alloc_page(&pa) == 0){
      r = OWNER1_POOL_BASE + (pa - KERNPOOL_TOP);
      memset((char*)r, 0, PGSIZE);
    }
    break;
  case SVC_PAGE_FREE:
    if(a >= OWNER1_POOL_BASE && a < OWNER1_POOL_END && a % PGSIZE == 0){
      pa = KERNPOOL_TOP + (a - OWNER1_POOL_BASE);
      if(root_page_is_allocated(pa)){   // never let a bad free panic the kernel
        memset((char*)a, 1, PGSIZE);
        root_free_page(pa);
        r = 0;
      }
    }
    break;
  case SVC_READ_BLOCK:
    if(owner1_range_ok(p, a, 512)){
      owner_read_block((void*)a);
      r = 0;
    }
    break;
  case SVC_EXPOSURE:
    r = rootpool_exposure(&total);      // page tables that map the pool
    r = r + 256 * total;                // packed: low byte = mapped, rest = tables looked at
    break;
  case SVC_SNAPSHOT:
    if(b == sizeof(struct psinfo) && (a & 3) == 0 && owner1_range_ok(p, a, b)){
      ps_snapshot((struct psinfo*)a);   // fills the Owner's own buffer; every page there is mapped
      r = 0;
    }
    break;
  case SVC_KILL:
    if((int)a <= 1 || (int)a == p->pid)
      r = -2;                          // pid 1 (init) and the Owner itself are never killed
    else
      r = kill((int)a) < 0 ? -1 : 0;   // -1: no such process
    break;
  case SVC_GETPID:
    r = p->pid;
    break;
  case SVC_KILLGROUP:
    r = kill_group((int)a);             // -2: System is never killed; -1: no such group
    break;
  case SVC_KINDRULE_SET:
    if(b == sizeof(kreq) && (a & 3) == 0 && owner1_range_ok(p, a, b)){
      memmove(&kreq, (char*)a, sizeof(kreq));
      r = kindrule_set(kreq.kind, kreq.which, kreq.limit, kreq.action);   // 0, or -1: bad arguments, or System
    }
    break;
  case SVC_REG_MODE:
    if(a == 0)
      r = registry_mode();
    else if(a == 1 && registry_set_mode((int)b) == 0)
      r = registry_mode();
    break;
  case SVC_REG_ENTRY:
    if(b == sizeof(rv) && (a & 3) == 0 && owner1_range_ok(p, a, b)){
      memmove(&rv, (char*)a, sizeof(rv));
      r = registry_entry(rv.index, &rv);
      memmove((char*)a, &rv, sizeof(rv));       // rv.total is filled in even past the end
    }
    break;
  case SVC_INST_READ:
    if(b == sizeof(struct inst_view) && (a & 3) == 0 && owner1_range_ok(p, a, b)){
      registry_inst_read((struct inst_view*)a);   // fills the Owner's own buffer; the status is inside it
      r = 0;
    }
    break;
  case SVC_INST_COMMIT:
    if(b == sizeof(irq) && (a & 3) == 0 && owner1_range_ok(p, a, b)){
      memmove(&irq, (char*)a, sizeof(irq));
      registry_inst_commit(&irq);              // called after the Owner's session has closed: no held writers
      memmove((char*)a, &irq, sizeof(irq));    // the status is inside it
      r = 0;
    }
    break;
  case SVC_UNINST:
    if(b == sizeof(urq) && (a & 3) == 0 && owner1_range_ok(p, a, b)){
      memmove(&urq, (char*)a, sizeof(urq));
      registry_uninstall(&urq);                // called after the Owner's session has closed: no held writers
      memmove((char*)a, &urq, sizeof(urq));    // the status is inside it
      r = 0;
    }
    break;
  case SVC_REPORT_READ:
    if(b == sizeof(struct rep_view) && (a & 3) == 0 && owner1_range_ok(p, a, b)){
      registry_report_read((struct rep_view*)a);   // fills the Owner's own buffer; the status is inside it
      r = 0;
    }
    break;
  case SVC_BUSY:
    owner_console_busy(a != 0);
    r = 0;
    break;
  case SVC_RULE_SET:
    if(b == sizeof(rq) && (a & 3) == 0 && owner1_range_ok(p, a, b)){
      memmove(&rq, (char*)a, sizeof(rq));
      rq.prog[sizeof(rq.prog) - 1] = 0;
      if(strncmp(rq.prog, "init", 16) == 0 || strncmp(rq.prog, "initcode", 16) == 0 ||
         strncmp(rq.prog, "owner", 16) == 0)
        r = -3;                          // no rule may name init or the Owner
      else
        r = rule_set(rq.prog, rq.which, rq.limit, rq.action, rq.scope);   // 0, -1 bad arguments, -2 table full
    }
    break;
  case SVC_RULE_REMOVE:
    if(b > 0 && b < sizeof(nm) && owner1_range_ok(p, a, b)){
      memmove(nm, (char*)a, b);
      nm[b] = 0;
      r = rule_remove(nm);               // 0, or -1 if there is no such program
    }
    break;
  case SVC_RULES_STATE:
    if(a == 0)
      r = apps_rules_dirty() || kindrules_dirty() || registry_dirty();
    else if(a == 1){
      rules_restore();
      registry_apps_reapply();               // an installed app's rules are its manifest's again
      kindrules_restore();
      registry_restore();
      r = 0;
    }
    break;
  case SVC_RULES_SAVE:
    if(!owner_fs_ready)
      r = -2;
    else if(rules_save_file() == 0){
      rules_snapshot();
      kindrules_snapshot();
      registry_snapshot();
      r = 0;
    }
    break;
  }
  tf->eax = r;
}

// ---- the fault policy (step 3e) ----
// A fault in the Ring 1 Owner never kills it and never stops the kernel: the Owner is reset to
// its start, the console is given back, and its Owner pool pages are scrubbed and freed. More
// than OWNER1_MAX_FAULTS faults within OWNER1_FAULT_WINDOW ticks stop it for good, and chords are
// ignored from then on, so the console can never be held by an Owner that is not running.

#define OWNER1_MAX_FAULTS   3
#define OWNER1_FAULT_WINDOW 10000

static struct spinlock owner1_stoplock;   // a zeroed spinlock is a valid unlocked lock
static int owner1_nfaults;
static uint owner1_last_fault;
static int owner1_stopped;                // the channel a stopped Owner sleeps on

void
owner1_fault(struct trapframe *tf)
{
  extern char _binary_owner1_start[], _binary_owner1_size[];
  struct proc *p = myproc();
  volatile uint zero = 0;
  char *img = (char*)zero;                // the Owner's address 0
  uint pa;

  cprintf("[Owner] fault at Ring 1: trap %d err %d at eip 0x%x\n", tf->trapno, tf->err, tf->eip);
  if(ticks - owner1_last_fault > OWNER1_FAULT_WINDOW)
    owner1_nfaults = 0;
  owner1_last_fault = ticks;
  owner1_nfaults++;

  owner_clear_requests();            // a chord pressed meanwhile must not start a session at once
  owner_console_close();             // give the keyboard and the screen back
  if(owner1_nfaults > OWNER1_MAX_FAULTS){
    cprintf("[Owner] too many faults: the Owner is stopped until reboot\n");
    owner_console_busy(1);           // chords are ignored from now on
    acquire(&owner1_stoplock);
    for(;;)
      sleep(&owner1_stopped, &owner1_stoplock);
  }
  owner_console_busy(0);

  // scrub and free every Owner pool page: the block copy is read again from disk at the next login
  for(pa = KERNPOOL_TOP; pa < ROOTPOOL_TOP; pa += PGSIZE)
    if(root_page_is_allocated(pa)){
      memset((char*)(OWNER1_POOL_BASE + (pa - KERNPOOL_TOP)), 1, PGSIZE);
      root_free_page(pa);
    }

  // the image as built (its data and zeroed data), and a clean stack
  memset(img, 0, p->sz);
  memmove(img, _binary_owner1_start, (uint)_binary_owner1_size);
  memset((char*)OWNER1_STACK_LO, 0, OWNER1_STACK_PAGES * PGSIZE);

  // back to the entry point at Ring 1
  memset(tf, 0, sizeof(*tf));
  tf->cs = (SEG_OCODE << 3) | DPL_OWNER;
  tf->ds = (SEG_ODATA << 3) | DPL_OWNER;
  tf->es = tf->ds;
  tf->ss = tf->ds;
  tf->eflags = FL_IF;
  tf->esp = OWNER1_STACK_TOP;
  tf->eip = 0;
  cprintf("[Owner] restarted\n");
}

// A fault at Ring 1, called from trap(): only the Owner runs there. Returns 1 if handled.
int
ring1_fault(struct trapframe *tf)
{
  struct proc *p = myproc();

  if(p && p->kproc == 2){            // the Owner: restart it
    owner1_fault(tf);
    return 1;
  }
  panic("ring1_fault: a fault at Ring 1 outside the Owner");
  return 0;
}
