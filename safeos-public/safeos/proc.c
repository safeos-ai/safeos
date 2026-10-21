#include "types.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "x86.h"
#include "proc.h"
#include "spinlock.h"
#include "rootowner.h"
#include "mempool.h"
#include "psinfo.h"

struct {
  struct spinlock lock;
  struct proc proc[NPROC];
} ptable;

static struct proc *initproc;
static struct proc *ownerproc;   // the Owner (pid 2): with workers present it runs on cpu0, with the scheduler

int nextpid = 1;
extern void forkret(void);
extern void trapret(void);

static void wakeup1(void *chan);

void
pinit(void)
{
  initlock(&ptable.lock, "ptable");
}

// Must be called with interrupts disabled
int
cpuid() {
  return mycpu()-cpus;
}

// Must be called with interrupts disabled to avoid the caller being
// rescheduled between reading lapicid and running through the loop.
struct cpu*
mycpu(void)
{
  int apicid, i;
  
  if(readeflags()&FL_IF)
    panic("mycpu called with interrupts enabled\n");
  
  apicid = lapicid();
  // APIC IDs are not guaranteed to be contiguous. Maybe we should have
  // a reverse map, or reserve a register to store &cpus[i].
  for (i = 0; i < ncpu; ++i) {
    if (cpus[i].apicid == apicid)
      return &cpus[i];
  }
  panic("unknown apicid\n");
}

// Disable interrupts so that we are not rescheduled
// while reading proc from the cpu structure
struct proc*
myproc(void) {
  struct cpu *c;
  struct proc *p;
  pushcli();
  c = mycpu();
  p = c->proc;
  popcli();
  return p;
}

//PAGEBREAK: 32
// Look in the process table for an UNUSED proc.
// If found, change state to EMBRYO and initialize
// state required to run in the kernel.
// Otherwise return 0.
static struct proc*
allocproc(void)
{
  struct proc *p;
  char *sp;

  acquire(&ptable.lock);

  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++)
    if(p->state == UNUSED)
      goto found;

  release(&ptable.lock);
  return 0;

found:
  p->state = EMBRYO;
  p->pid = nextpid++;
  p->last_cpu = -1;
  p->kproc = 0;
  p->gid = 0;
  p->ucpu = 0;
  p->qtick = (uint)-1;
  memset(&p->res, 0, sizeof(p->res));
  memset(p->fpu, 0, sizeof(p->fpu));   // no stale x87 image from the process that used this slot before
  p->res.start_tick = ticks;

  release(&ptable.lock);

  // Allocate kernel stack.
  if((p->kstack = kalloc()) == 0){
    p->state = UNUSED;
    return 0;
  }
  sp = p->kstack + KSTACKSIZE;

  // Leave room for trap frame.
  sp -= sizeof *p->tf;
  p->tf = (struct trapframe*)sp;

  // Set up new context to start executing at forkret,
  // which returns to trapret.
  sp -= 4;
  *(uint*)sp = (uint)trapret;

  sp -= sizeof *p->context;
  p->context = (struct context*)sp;
  memset(p->context, 0, sizeof *p->context);
  p->context->eip = (uint)forkret;

  return p;
}

//PAGEBREAK: 32
// Set up first user process.
void
userinit(void)
{
  struct proc *p;
  extern char _binary_initcode_start[], _binary_initcode_size[];

  p = allocproc();
  
  initproc = p;
  if((p->pgdir = setupkvm()) == 0)
    panic("userinit: out of memory?");
  inituvm(p->pgdir, _binary_initcode_start, (int)_binary_initcode_size);
  p->sz = PGSIZE;
  memset(p->tf, 0, sizeof(*p->tf));
  p->tf->cs = (SEG_UCODE << 3) | DPL_USER;
  p->tf->ds = (SEG_UDATA << 3) | DPL_USER;
  p->tf->es = p->tf->ds;
  p->tf->ss = p->tf->ds;
  p->tf->eflags = FL_IF;
  p->tf->esp = PGSIZE;
  p->tf->eip = 0;  // beginning of initcode.S

  safestrcpy(p->name, "initcode", sizeof(p->name));
  p->cwd = namei("/");

  // this assignment to p->state lets other cores
  // run this process. the acquire forces the above
  // writes to be visible, and the lock is also needed
  // because the assignment might not be atomic.
  acquire(&ptable.lock);

  p->state = RUNNABLE;

  release(&ptable.lock);
}

// Grow current process's memory by n bytes.
// Return 0 on success, -1 on failure.
int
growproc(int n)
{
  uint sz;
  struct proc *curproc = myproc();

  sz = curproc->sz;
  if(n > 0){
    if((sz = allocuvm(curproc->pgdir, sz, sz + n)) == 0)
      return -1;
  } else if(n < 0){
    if((sz = deallocuvm(curproc->pgdir, sz, sz + n)) == 0)
      return -1;
  }
  curproc->sz = sz;
  switchuvm(curproc);
  return 0;
}

// Create a new process copying p as the parent.
// Sets up stack to return as if from system call.
// Caller must set state of returned proc to RUNNABLE.
int group_fork_ok(struct proc *p);   // groups, at the end of this file

int
fork(void)
{
  int i, pid;
  struct proc *np;
  struct proc *curproc = myproc();

  if(!group_fork_ok(curproc))
    return -1;                       // the Owner is killing this group

  // Allocate process.
  if((np = allocproc()) == 0){
    return -1;
  }
  np->gid = curproc->gid;             // a child is in its parent's group from the start

  // Copy process state from proc.
  if((np->pgdir = copyuvm(curproc->pgdir, curproc->sz)) == 0){
    kfree(np->kstack);
    np->kstack = 0;
    np->state = UNUSED;
    return -1;
  }
  np->sz = curproc->sz;
  np->parent = curproc;
  *np->tf = *curproc->tf;

  // Clear %eax so that fork returns 0 in the child.
  np->tf->eax = 0;

  for(i = 0; i < NOFILE; i++)
    if(curproc->ofile[i])
      np->ofile[i] = filedup(curproc->ofile[i]);
  np->cwd = idup(curproc->cwd);

  safestrcpy(np->name, curproc->name, sizeof(curproc->name));

  pid = np->pid;

  acquire(&ptable.lock);

  np->state = RUNNABLE;

  release(&ptable.lock);

  return pid;
}

// Exit the current process.  Does not return.
// An exited process remains in the zombie state
// until its parent calls wait() to find out it exited.
void
exit(void)
{
  struct proc *curproc = myproc();
  struct proc *p;
  int fd;

  if(curproc == initproc)
    panic("init exiting");

  // Close all open files.
  for(fd = 0; fd < NOFILE; fd++){
    if(curproc->ofile[fd]){
      fileclose(curproc->ofile[fd]);
      curproc->ofile[fd] = 0;
    }
  }

  begin_op();
  iput(curproc->cwd);
  end_op();
  curproc->cwd = 0;

  acquire(&ptable.lock);

  // Parent might be sleeping in wait().
  wakeup1(curproc->parent);

  // Pass abandoned children to init.
  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
    if(p->parent == curproc){
      p->parent = initproc;
      if(p->state == ZOMBIE)
        wakeup1(initproc);
    }
  }

  // Jump into the scheduler, never to return.
  curproc->state = ZOMBIE;
  sched();
  panic("zombie exit");
}

// Wait for a child process to exit and return its pid.
// Return -1 if this process has no children.
int
wait(void)
{
  struct proc *p;
  int havekids, pid;
  struct proc *curproc = myproc();
  
  acquire(&ptable.lock);
  for(;;){
    // Scan through table looking for exited children.
    havekids = 0;
    for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
      if(p->parent != curproc)
        continue;
      havekids = 1;
      if(p->state == ZOMBIE){
        // Found one.
        pid = p->pid;
        kfree(p->kstack);
        p->kstack = 0;
        freevm(p->pgdir);
        p->pid = 0;
        p->parent = 0;
        p->name[0] = 0;
        p->killed = 0;
        p->state = UNUSED;
        release(&ptable.lock);
        return pid;
      }
    }

    // No point waiting if we don't have any children.
    if(!havekids || curproc->killed){
      release(&ptable.lock);
      return -1;
    }

    // Wait for children to exit.  (See wakeup1 call in proc_exit.)
    sleep(curproc, &ptable.lock);  //DOC: wait-sleep
  }
}

// Dispatch and run one process on the calling CPU, synchronously.
// Caller must hold ptable.lock and have already confirmed p->state == RUNNABLE.
static void
run_process_here(struct cpu *c, struct proc *p)
{
  c->proc = p;
  p->last_cpu = cpuid();
  switchuvm(p);
  p->state = RUNNING;

  swtch(&(c->scheduler), p->context);
  switchkvm();

  // Process is done running for now.
  // It should have changed its p->state before coming back.
  c->proc = 0;
}

// Find an idle worker CPU (not cpu0, which is the global scheduler).
// Caller must hold ptable.lock. Returns 0 if none are idle right now.
static struct cpu*
find_idle_worker(void)
{
  struct cpu *w;
  for(w = cpus + 1; w < cpus + ncpu; w++){
    if(w->idle)
      return w;
  }
  return 0;
}

//PAGEBREAK: 42
// Per-CPU process scheduler.
// Each CPU calls scheduler() after setting itself up.
// Scheduler never returns.  It loops, doing:
//  - choose a process to run
//  - swtch to start running that process
//  - eventually that process transfers control
//      via swtch back to the scheduler.
static int rr_next;   // round-robin cursor: the slot after the last assignment

// Pause hint for spin-wait loops. The "memory" clobber also makes the
// compiler reread shared flags on every pass.
static inline void
cpu_relax(void)
{
  asm volatile("pause" : : : "memory");
}

// Unlocked hint: is any process RUNNABLE? Only a hint. The real decision is
// made again under ptable.lock.
static int
hint_runnable(void)
{
  struct proc *p;

  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++)
    if(*(volatile enum procstate *)&p->state == RUNNABLE)
      return 1;
  return 0;
}

// Unlocked hint, like hint_runnable: is the Owner waiting to run? It runs on this CPU, so it must not wait for an idle worker.
static int
hint_owner_runnable(void)
{
  return ownerproc != 0 && *(volatile enum procstate *)&ownerproc->state == RUNNABLE;
}

void
global_scheduler(void)
{

  struct proc *p;
  int k, start;
  int idlespins = 0;
  struct cpu *c = mycpu();
  c->proc = 0;

  for(;;){
    sti();

    // With workers present, stay off ptable.lock unless there is both
    // something to hand out and someone to hand it to. find_idle_worker()
    // only reads here, so calling it without the lock is fine as a hint.
    // After 10000 idle spins take a locked pass anyway, so a wrong hint
    // can never stall scheduling.
    if(ncpu > 1 && idlespins < 10000 && !hint_owner_runnable() &&
       (find_idle_worker() == 0 || !hint_runnable())){
      idlespins++;
      cpu_relax();
      continue;
    }
    idlespins = 0;

    acquire(&ptable.lock);
    start = rr_next;                // one cursor for the whole pass
    for(k = 0; k < NPROC; k++){
      p = &ptable.proc[(start + k) % NPROC];
      if(p->state != RUNNABLE)
        continue;

      if(ncpu == 1 || p == ownerproc){     // the Owner runs here, on the scheduler core
        run_process_here(c, p);
      } else {
        struct cpu *w = find_idle_worker();
        if(w == 0)
          continue;          // all workers busy - revisit on next pass
        w->assigned = p;
        p->state = ASSIGNED;   // claim it: later scans no longer see it as RUNNABLE
        rr_next = (p - ptable.proc + 1) % NPROC;
        w->idle = 0;
      }
    }
    release(&ptable.lock);
  }
}

void
worker_loop(void)
{
  struct cpu *c = mycpu();
  c->proc = 0;
  c->idle = 1;

  for(;;){
    sti();
    if(c->assigned != 0){
      acquire(&ptable.lock);
      struct proc *p = c->assigned;
      c->assigned = 0;
      if(p->state != ASSIGNED)
        panic("worker: assigned process is not ASSIGNED");
      run_process_here(c, p);
      release(&ptable.lock);
      c->idle = 1;
    } else {
      cpu_relax();
    }
  }
}

// Enter scheduler.  Must hold only ptable.lock
// and have changed proc->state. Saves and restores
// intena because intena is a property of this
// kernel thread, not this CPU. It should
// be proc->intena and proc->ncli, but that would
// break in the few places where a lock is held but
// there's no process.
void
sched(void)
{
  int intena;
  struct proc *p = myproc();

  if(!holding(&ptable.lock))
    panic("sched ptable.lock");
  if(mycpu()->ncli != 1)
    panic("sched locks");
  if(p->state == RUNNING)
    panic("sched running");
  if(readeflags()&FL_IF)
    panic("sched interruptible");
  intena = mycpu()->intena;
  // The x87 state travels with the process: fnsave saves it and also clears the FPU, so the next
  // process starts clean; frstor puts this process's own state back when it runs again.
  asm volatile("fnsave (%0)" : : "r"(p->fpu) : "memory");
  swtch(&p->context, mycpu()->scheduler);
  asm volatile("frstor (%0)" : : "r"(p->fpu) : "memory");
  mycpu()->intena = intena;
}

// Give up the CPU for one scheduling round.
void
yield(void)
{
  acquire(&ptable.lock);  //DOC: yieldlock
  myproc()->state = RUNNABLE;
  sched();
  release(&ptable.lock);
}

// A fork child's very first scheduling by scheduler()
// will swtch here.  "Return" to user space.
void
forkret(void)
{
  static int first = 1;
  // Still holding ptable.lock from scheduler.
  release(&ptable.lock);

  if (first) {
    // Some initialization functions must be run in the context
    // of a regular process (e.g., they call sleep), and thus cannot
    // be run from main().
    first = 0;
    iinit(ROOTDEV);
    initlog(ROOTDEV);
    root_fs_up();     // Owner-Mode: one hook, see root/owner/rootfsup.c
  }

  // Return to "caller", actually trapret (see allocproc).
}

// Atomically release lock and sleep on chan.
// Reacquires lock when awakened.
void
sleep(void *chan, struct spinlock *lk)
{
  struct proc *p = myproc();
  
  if(p == 0)
    panic("sleep");

  if(lk == 0)
    panic("sleep without lk");

  // Must acquire ptable.lock in order to
  // change p->state and then call sched.
  // Once we hold ptable.lock, we can be
  // guaranteed that we won't miss any wakeup
  // (wakeup runs with ptable.lock locked),
  // so it's okay to release lk.
  if(lk != &ptable.lock){  //DOC: sleeplock0
    acquire(&ptable.lock);  //DOC: sleeplock1
    release(lk);
  }
  // Go to sleep.
  p->chan = chan;
  p->state = SLEEPING;

  sched();

  // Tidy up.
  p->chan = 0;

  // Reacquire original lock.
  if(lk != &ptable.lock){  //DOC: sleeplock2
    release(&ptable.lock);
    acquire(lk);
  }
}

//PAGEBREAK!
// Wake up all processes sleeping on chan.
// The ptable lock must be held.
static void
wakeup1(void *chan)
{
  struct proc *p;

  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++)
    if(p->state == SLEEPING && p->chan == chan)
      p->state = RUNNABLE;
}

// Wake up all processes sleeping on chan.
void
wakeup(void *chan)
{
  acquire(&ptable.lock);
  wakeup1(chan);
  release(&ptable.lock);
}

// Kill the process with the given pid.
// Process won't exit until it returns
// to user space (see trap in trap.c).
int
kill(int pid)
{
  struct proc *p;

  acquire(&ptable.lock);
  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
    if(p->pid == pid){
      if(p->kproc){              // the Owner process cannot be killed
        release(&ptable.lock);
        return -1;
      }
      p->killed = 1;
      // Wake process from sleep if necessary.
      if(p->state == SLEEPING)
        p->state = RUNNABLE;
      release(&ptable.lock);
      return 0;
    }
  }
  release(&ptable.lock);
  return -1;
}

//PAGEBREAK: 36
// Print a process listing to console.  For debugging.
// Runs when user types ^P on console.
// No lock to avoid wedging a stuck machine further.
void
procdump(void)
{
  static char *states[] = {
  [UNUSED]    "unused",
  [EMBRYO]    "embryo",
  [SLEEPING]  "sleep ",
  [RUNNABLE]  "runble",
  [RUNNING]   "run   ",
  [ZOMBIE]    "zombie",
  [ASSIGNED]  "assign"
  };
  int i;
  struct proc *p;
  char *state;
  uint pc[10];

  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
    if(p->state == UNUSED)
      continue;
    if(p->state >= 0 && p->state < NELEM(states) && states[p->state])
      state = states[p->state];
    else
      state = "???";
    cprintf("%d %s %s", p->pid, state, p->name);
    if(p->state == SLEEPING){
      getcallerpcs((uint*)p->context->ebp+2, pc);
      for(i=0; i<10 && pc[i] != 0; i++)
        cprintf(" %p", pc[i]);
    }
    cprintf("\n");
  }
}

// Print a table of currently active processes (used by ps).
// moved to pskernel.c
// Counts the live page tables that map the Owner pool: only the Owner's should.
// *total gets the number of page tables looked at. A debugging probe for the
// Owner's rootmem command; a process in the middle of exec can be miscounted.
int
rootpool_exposure(int *total)
{
  struct proc *p;
  int n = 0, t = 0;

  acquire(&ptable.lock);
  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
    if(p->state == UNUSED || p->state == EMBRYO || p->pgdir == 0)
      continue;
    t++;
    if(pgdir_maps_pool(p->pgdir))
      n++;
  }
  release(&ptable.lock);
  *total = t;
  return n;
}


// ---- the Owner as a Ring 1 process (step 3a) ----

// Like forkret, minus the one-time file system start-up, which belongs to process 1.
static void
owner1ret(void)
{
  release(&ptable.lock);
}

void
owner1_proc_create(void)
{
  extern char _binary_owner1_start[], _binary_owner1_size[];
  struct proc *p;
  uint size = (uint)_binary_owner1_size, npg, i, n;
  char *pg;

  if(size == 0 || size > OWNER1_MAX_IMAGE)
    panic("owner1: bad image size");
  p = allocproc();
  if(p == 0)
    panic("owner1: no process slot");
  if((p->pgdir = setupkvm()) == 0)
    panic("owner1: out of memory");
  npg = PGROUNDUP(size) / PGSIZE;
  for(i = 0; i < npg; i++){                   // the image, at address 0
    if((pg = kalloc()) == 0)
      panic("owner1: out of memory");
    memset(pg, 0, PGSIZE);
    n = size - i * PGSIZE;
    memmove(pg, _binary_owner1_start + i * PGSIZE, n < PGSIZE ? n : PGSIZE);
    if(map_ring1_page(p->pgdir, i * PGSIZE, pg) < 0)
      panic("owner1: cannot map");
  }
  for(i = 0; i < OWNER1_STACK_PAGES; i++){    // the stack
    if((pg = kalloc()) == 0)
      panic("owner1: out of memory");
    memset(pg, 0, PGSIZE);
    if(map_ring1_page(p->pgdir, OWNER1_STACK_LO + i * PGSIZE, pg) < 0)
      panic("owner1: cannot map");
  }
  if(map_ownerpool_low(p->pgdir) < 0)
    panic("owner1: cannot map the Owner pool");
  p->sz = npg * PGSIZE;                        // end of the image: the dispatcher checks against it
  p->kproc = 2;                                // 2 = Owner at Ring 1: kill() refuses it, no console hold
  p->parent = 0;
  memset(p->tf, 0, sizeof(*p->tf));
  ownerproc = p;                               // the scheduler on cpu0 runs the Owner itself
  p->tf->cs = (SEG_OCODE << 3) | DPL_OWNER;
  p->tf->ds = (SEG_ODATA << 3) | DPL_OWNER;
  p->tf->es = p->tf->ds;
  p->tf->ss = p->tf->ds;
  p->tf->eflags = FL_IF;
  p->tf->esp = OWNER1_STACK_TOP;
  p->tf->eip = 0;
  p->context->eip = (uint)owner1ret;
  safestrcpy(p->name, "owner", sizeof(p->name));

  acquire(&ptable.lock);
  p->state = RUNNABLE;
  release(&ptable.lock);
}

// ---- process groups ----
// Every process has a group, p->gid. Group 0, System, holds init and the Owner; group 2, Utilities, holds the shell and the utilities it starts.
// At exec the group follows the provider table (rootgroups.c): a process already in an AI agent's group
// stays there, whatever it runs; a utility stays in its caller's group (System starts the Utilities group); anything else gets a group
// named after its program. A program the provider did not list is an AI agent. Member counts are not
// kept: they are derived from the process table. The table and every p->gid are protected by ptable.lock.

struct group_entry {
  char name[16];
  int  kind;       // GK_*
  int  used;
  int  dying;      // the Owner is killing this group: forks into it are refused
  uint cpu;       // CPU ticks charged to the group since it was made
  uint cpubase;    // the value of cpu when the current run was launched: the cputime rule counts from here
  uchar over[4];  // already reported as over the CPU limit, and the memory limit: report once per crossing
};

static struct group_entry grouptab[PS_MAXGROUP] = {
  [0] = { "System", GK_SYSTEM, 1, 0 },
  [1] = { "Other",  GK_AGENT,  1, 0 },    // where programs go when the table is full
  [2] = { "Utilities", GK_UTILITY, 1, 0 },   // the shell and the utilities it starts
};

// ---- recent CPU use ----
// Each timer tick charges the group of the process that is running (group_cpu_tick). Every USAGE_STEP
// ticks cpu0's timer copies every group's total, and every process's pid and CPU total, into a ring.
// The figures shown are the newest total minus the oldest sample: the use over about
// USAGE_STEP * (USAGE_RING - 1) ticks. A process whose pid is not in the oldest sample is newer than the
// window, so all of its CPU time counts.
static struct {
  uint at;                      // the tick of the sample
  uint gcpu[PS_MAXGROUP];       // each group's total at that tick
  int  pid[NPROC];              // the pid in each process slot at that tick (0 = unused)
  uint pcpu[NPROC];             // that process's CPU ticks at that tick
} usage_ring[USAGE_RING];
static volatile int usage_n;    // samples taken so far; only usage_sample writes it, under ptable.lock

void
usage_charge(void)              // called from cpu0's timer interrupt, once per tick
{
  int i;
  struct proc *p;

  // Look at what each worker is running at this instant and charge that process one tick. A process is
  // on one CPU at a time, so it is charged at most once per tick, and the total cannot exceed the number
  // of workers. (Charging from every CPU's own timer counted a process twice when it moved between workers.)
  for(i = (ncpu == 1) ? 0 : 1; i < ncpu; i++){
    p = cpus[i].proc;
    if(p && p->state == RUNNING){
      p->ucpu++;
      grouptab[p->gid].cpu++;
    }
  }
  if(ncpu > 1 && ownerproc != 0 && cpus[0].proc == ownerproc && ownerproc->state == RUNNING){   // the Owner runs on cpu0 itself
    ownerproc->ucpu++;
  }
}

int proc_mem_pages(struct proc *p);                                           // below
int pool_info(int which, char *name, int namelen, int *nfree, int *ntotal);   // kalloc.c
static int kill_group_locked(int gid);                                        // below

// ---- limits per kind of group ----
// Every USAGE_STEP ticks, after a sample is stored, each App, Agent and Utilities group is compared with
// the limit for its kind: its CPU over the recent window, and the pages its processes hold. System is never
// checked. Nothing is judged until the window is 500 ticks old. Messages are queued while ptable.lock is held
// and printed after it is released, because cprintf never nests inside another lock.
static char *kind_label[] = { "System", "App", "Agent", "Utilities" };

struct kr_msg {
  char name[16];
  int  kind, which, val10, limit, killed;
};
static struct kr_msg krm[6 * PS_MAXGROUP];     // only cpu0's timer fills it, so a static array is safe

static int
kr_check_locked(int total)       // the caller holds ptable.lock; returns the number of messages queued
{
  int g, s, w, nm = 0, cap, lim, act, val, thr, window;
  int cnt[PS_MAXGROUP], mem[PS_MAXGROUP], out[PS_MAXGROUP];
  uint oldat, oldg[PS_MAXGROUP], cpuused;
  struct proc *p;

  s = (usage_n < USAGE_RING) ? 0 : usage_n % USAGE_RING;     // the oldest sample in the ring
  oldat = usage_ring[s].at;
  window = (int)(ticks - oldat);
  if(window < 500 || total <= 0)
    return 0;                                                // too young to judge
  for(g = 0; g < PS_MAXGROUP; g++){
    oldg[g] = usage_ring[s].gcpu[g];
    cnt[g] = 0;
    mem[g] = 0;
    out[g] = 0;
    out[g] = 0;
  }
  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
    if(p->state == UNUSED)
      continue;
    mem[p->gid] += proc_mem_pages(p);                        // exited processes keep their pages until reaped
    if(p->state != ZOMBIE && p->state != EMBRYO){
      cnt[p->gid]++;
      out[p->gid] += p->res.used[RES_STDOUT];       // console writes of the live processes
    }
  }
  cap = window * ((ncpu == 1) ? 1 : ncpu - 1);
  for(g = 1; g < PS_MAXGROUP; g++){                          // group 0, System, is never limited
    if(!grouptab[g].used || cnt[g] == 0)
      continue;
    for(w = 0; w < 4; w++){
      lim = kindrule_get(grouptab[g].kind, w, &act);
      if(lim <= 0)
        continue;
      if(w == KR_CPU){
        cpuused = grouptab[g].cpu - oldg[g];
        val = (int)((cpuused * 1000 + cap / 2) / cap);       // tenths of a percent of the whole machine
        thr = lim * 10;
      } else if(w == KR_MEM){
        val = (mem[g] * 1000 + total / 2) / total;
        thr = lim * 10;
      } else if(w == KR_CPUTIME){
        val = (int)(grouptab[g].cpu - grouptab[g].cpubase);   // CPU ticks since this run was launched
        thr = lim;
      } else {
        val = out[g];                                         // console writes of its live processes
        thr = lim;
      }
      if(val <= thr){
        grouptab[g].over[w] = 0;
        continue;
      }
      safestrcpy(krm[nm].name, grouptab[g].name, sizeof(krm[nm].name));
      krm[nm].kind = grouptab[g].kind;
      krm[nm].which = w;
      krm[nm].val10 = val;
      krm[nm].limit = lim;
      krm[nm].killed = 0;
      if((act & ACTION_KILL) && !grouptab[g].dying && kill_group_locked(g) > 0){
        krm[nm].killed = 1;
        nm++;
      } else if((act & ACTION_REPORT) && !grouptab[g].over[w])
        nm++;                                                // report once per crossing
      grouptab[g].over[w] = 1;
    }
  }
  return nm;
}

void
usage_sample(void)              // called from cpu0's timer interrupt every USAGE_STEP ticks
{
  int s, g, i, nm, total = 0, f, t;
  char pname[16];
  struct proc *p;

  for(i = 0; pool_info(i, pname, sizeof(pname), &f, &t) >= 0; i++)   // pool locks are never taken under ptable.lock
    total += t;
  acquire(&ptable.lock);
  s = usage_n % USAGE_RING;
  usage_ring[s].at = ticks;
  for(g = 0; g < PS_MAXGROUP; g++)
    usage_ring[s].gcpu[g] = grouptab[g].cpu;
  for(i = 0, p = ptable.proc; p < &ptable.proc[NPROC]; p++, i++){
    if(p->state == UNUSED){
      usage_ring[s].pid[i] = 0;
      usage_ring[s].pcpu[i] = 0;
    } else {
      usage_ring[s].pid[i] = p->pid;
      usage_ring[s].pcpu[i] = p->ucpu;
    }
  }
  usage_n++;
  nm = kr_check_locked(total);
  release(&ptable.lock);
  for(i = 0; i < nm; i++){
    if(krm[i].which < 2)
      cprintf("[Owner policy] %s (%s): %s %d.%d%%, limit %d%%: %s\n",
              krm[i].kind == GK_UTILITY ? "all utilities" : krm[i].name, kind_label[krm[i].kind],
              krm[i].which == KR_CPU ? "CPU" : "memory", krm[i].val10 / 10, krm[i].val10 % 10, krm[i].limit,
              krm[i].killed ? "group killed" : "reported");
    else
      cprintf("[Owner policy] %s (%s): %s %d, limit %d: %s\n",
              krm[i].kind == GK_UTILITY ? "all utilities" : krm[i].name, kind_label[krm[i].kind],
              krm[i].which == KR_CPUTIME ? "cputime" : "stdout", krm[i].val10, krm[i].limit,
              krm[i].killed ? "group killed" : "reported");
  }
}


// ---- the name of the App or Agent group a process is in ----
int
group_app_name(struct proc *p, char *buf, int n)
{
  int ok = 0;

  if(p->gid < 3)
    return 0;                        // System, Other and Utilities have no rows of their own: no lock needed
  acquire(&ptable.lock);
  if(p->gid < PS_MAXGROUP && grouptab[p->gid].used &&
     (grouptab[p->gid].kind == GK_APP || grouptab[p->gid].kind == GK_AGENT)){
    safestrcpy(buf, grouptab[p->gid].name, n);
    ok = 1;
  }
  release(&ptable.lock);
  return ok;
}

// ---- an installed app's own limits, checked on every tick ----
// The rows with group scope (an installed app's manifest limits) are compared with the app's group on every tick of cpu0's
// timer. CPU time is compared here. Output is counted at every write (group_stdout_charge in resource.c), which notes the first
// crossing, and this function stops the group. Messages are queued while ptable.lock is held and printed after it is released.
static struct kr_msg am[2 * PS_MAXGROUP];      // only cpu0's timer fills it, so a static array is safe

void
app_check(void)
{
  int g, i, w, nm = 0, val, lim, act, crossed, which;
  int cnt[PS_MAXGROUP];
  struct proc *p;

  acquire(&ptable.lock);
  for(g = 0; g < PS_MAXGROUP; g++)
    cnt[g] = 0;
  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++)
    if(p->state != UNUSED && p->state != ZOMBIE && p->state != EMBRYO)
      cnt[p->gid]++;
  for(g = 3; g < PS_MAXGROUP; g++){
    if(!grouptab[g].used || cnt[g] == 0)
      continue;
    if(grouptab[g].kind != GK_APP && grouptab[g].kind != GK_AGENT)
      continue;                                        // only apps and agents have rows of their own
    for(w = KR_CPUTIME; w <= KR_STDOUT; w++){
      which = (w == KR_CPUTIME) ? RES_CPUTIME : RES_STDOUT;
      val = (int)(grouptab[g].cpu - grouptab[g].cpubase);   // CPU ticks of this launch; for output the check sets val itself
      lim = resource_group_check(grouptab[g].name, which, &val, &act, &crossed);
      if(lim <= 0)
        continue;
      if(w == KR_CPUTIME ? val <= lim : !crossed)
        continue;
      safestrcpy(am[nm].name, grouptab[g].name, sizeof(am[nm].name));
      am[nm].kind = grouptab[g].kind;
      am[nm].which = w;
      am[nm].val10 = val;
      am[nm].limit = lim;
      am[nm].killed = 0;
      if((act & ACTION_KILL) && !grouptab[g].dying && kill_group_locked(g) > 0){
        am[nm].killed = 1;
        nm++;
      } else if((act & ACTION_REPORT) && crossed)
        nm++;                                          // report once per crossing
    }
  }
  release(&ptable.lock);
  for(i = 0; i < nm; i++)
    cprintf("[Owner policy] %s (%s): %s %d, limit %d: %s\n", am[i].name, kind_label[am[i].kind],
            am[i].which == KR_CPUTIME ? "cputime" : "stdout", am[i].val10, am[i].limit,
            am[i].killed ? "group killed" : "reported");
}

int
group_fork_ok(struct proc *p)
{
  return !grouptab[p->gid].dying;          // a plain read of one int
}

// Called by exec once the new image is committed. name is the new program's name.
void
group_exec(struct proc *p, char *name)
{
  int pk = provider_kind(name);
  int gk, i, j, live, slot = -1, inuse[PS_MAXGROUP];
  struct proc *q;

  if(pk == PK_SYSTEM && p->pid != 1)
    pk = PK_AGENT;                         // only the first process may be System
  acquire(&ptable.lock);
  if(grouptab[p->gid].kind == GK_AGENT){   // an AI agent keeps everything it starts
    release(&ptable.lock);
    return;
  }
  if(pk == PK_SYSTEM){
    p->gid = 0;
    release(&ptable.lock);
    return;
  }
  if(pk == PK_TOOL){                       // a utility runs in its caller's group...
    if(p->gid == 0){                       // ...except that System starts the Utilities group (the shell)
      grouptab[2].dying = 0;               // a new shell after a killgroup: the kill is over
      p->gid = 2;
    }
    release(&ptable.lock);
    return;
  }
  gk = (pk == PK_APP) ? GK_APP : GK_AGENT;
  for(i = 3; i < PS_MAXGROUP; i++)
    if(grouptab[i].used && grouptab[i].kind == gk && strncmp(grouptab[i].name, name, 16) == 0){
      if(i != p->gid){
        grouptab[i].dying = 0;             // a new launch into the group: an earlier kill is over
        for(live = 0, q = ptable.proc; q < &ptable.proc[NPROC]; q++)
          if(q != p && q->gid == i && q->state != UNUSED && q->state != ZOMBIE && q->state != EMBRYO)
            live = 1;
        if(!live){                          // nothing of the old run is left: start again from scratch
          grouptab[i].cpu = 0;
          memset(grouptab[i].over, 0, sizeof(grouptab[i].over));
          resource_group_launch(name);        // the app's own rows count from zero again
          for(j = 0; j < USAGE_RING; j++)
            usage_ring[j].gcpu[i] = 0;
        }
      }
      p->gid = i;
      release(&ptable.lock);
      return;
    }
  for(i = 0; i < PS_MAXGROUP; i++)
    inuse[i] = 0;
  for(q = ptable.proc; q < &ptable.proc[NPROC]; q++)
    if(q->state != UNUSED)
      inuse[q->gid] = 1;
  for(i = 3; i < PS_MAXGROUP; i++)
    if(!grouptab[i].used || !inuse[i]){    // a free slot, or a group with no process left
      slot = i;
      break;
    }
  if(slot < 0){
    p->gid = 1;                            // the table is full: the shared Other group
  } else {
    safestrcpy(grouptab[slot].name, name, sizeof(grouptab[slot].name));
    grouptab[slot].kind = gk;
    grouptab[slot].used = 1;
    grouptab[slot].dying = 0;
    grouptab[slot].cpu = 0;                  // a reused slot starts its usage from zero
    grouptab[slot].cpubase = 0;
    memset(grouptab[slot].over, 0, sizeof(grouptab[slot].over));
    resource_group_launch(name);
    for(i = 0; i < USAGE_RING; i++)
      usage_ring[i].gcpu[slot] = 0;
    p->gid = slot;
  }
  release(&ptable.lock);
}

// Count the page tables of a page directory. They come from the kernel pool.
static int
count_tables(pde_t *pgdir)
{
  int i, n = 0;

  for(i = 0; i < NPDENTRIES; i++)
    if(pgdir[i] & PTE_P)
      n++;
  return n;
}

// The pages a process holds (a zombie keeps them until its parent reaps it): its kernel stack and page directory, its page tables, and its user
// pages (for the Ring 1 Owner, its image and stack). The caller holds ptable.lock. A page directory that
// exec replaces at this very moment can give a wrong count for one snapshot; it cannot fault.
int
proc_mem_pages(struct proc *p)
{
  int n = 0;

  if(p->state == UNUSED)
    return 0;
  if(p->kstack)
    n++;                                 // the kernel stack
  if(p->state == EMBRYO || p->pgdir == 0)
    return n;                            // still being created: its page directory is not valid yet
  n += 1 + count_tables(p->pgdir);       // the page directory and its page tables
  if(p->kproc == 2)
    n += (PGROUNDUP(p->sz) / PGSIZE) + OWNER1_STACK_PAGES;   // the Ring 1 Owner's image and stack
  else if(p->kproc == 0)
    n += PGROUNDUP(p->sz) / PGSIZE;      // user pages
  return n;
}

// CPU ticks a process used over the recent window. The caller holds ptable.lock.
int
proc_cpu_recent(struct proc *p)
{
  int i = (int)(p - ptable.proc), s;
  uint old = 0;

  if(usage_n > 0){
    s = (usage_n < USAGE_RING) ? 0 : usage_n % USAGE_RING;    // the oldest sample in the ring
    if(usage_ring[s].pid[i] == p->pid)
      old = usage_ring[s].pcpu[i];
  }
  return (int)(p->ucpu - old);
}

// Fill out->group from the snapshot's process list: the live process count of each group, its memory (the
// sum over its processes) and its CPU use over the recent window. The caller holds ptable.lock.
void
group_fill_locked(struct psinfo *out)
{
  int i, g, n = 0, cnt[PS_MAXGROUP], mem[PS_MAXGROUP], s;
  uint oldat = 0, oldg[PS_MAXGROUP];

  for(i = 0; i < PS_MAXGROUP; i++){
    cnt[i] = 0;
    mem[i] = 0;
    oldg[i] = 0;
  }
  for(i = 0; i < out->nproc; i++){
    g = out->proc[i].gid;
    if(g < 0 || g >= PS_MAXGROUP)
      continue;
    mem[g] += out->proc[i].mem_pages;                    // a zombie's pages stay charged to its group until it is reaped
    if(strncmp(out->proc[i].state, "zombie", 6) != 0 &&  // an exited process waiting to be reaped is not counted
       strncmp(out->proc[i].state, "embryo", 6) != 0)    // a process still being created is not counted
      cnt[g]++;
  }
  if(usage_n > 0){
    s = (usage_n < USAGE_RING) ? 0 : usage_n % USAGE_RING;
    oldat = usage_ring[s].at;
    for(i = 0; i < PS_MAXGROUP; i++)
      oldg[i] = usage_ring[s].gcpu[i];
  }
  out->usage_window = (int)(ticks - oldat);
  out->usage_workers = (ncpu == 1) ? 1 : ncpu - 1;
  for(i = 0; i < PS_MAXGROUP; i++){
    if(!grouptab[i].used || (i != 0 && cnt[i] == 0 && mem[i] == 0))
      continue;                            // no live process and no pages: not listed. Exited processes keep their pages charged here until reaped
    out->group[n].id = i;
    safestrcpy(out->group[n].name, grouptab[i].name, sizeof(out->group[n].name));
    out->group[n].kind = grouptab[i].kind;
    out->group[n].nproc = cnt[i];
    out->group[n].cpu_ticks = (int)(grouptab[i].cpu - oldg[i]);
    out->group[n].mem_pages = mem[i];
    n++;
  }
  out->ngroup = n;
}

static int
kill_group_locked(int gid)      // the caller holds ptable.lock and gid is a listed group
{
  struct proc *p;
  int n = 0;

  grouptab[gid].dying = 1;
  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
    if(p->state == UNUSED || p->state == EMBRYO || p->state == ZOMBIE ||
       p->gid != gid || p->pid <= 1 || p->kproc)
      continue;
    p->killed = 1;
    if(p->state == SLEEPING)
      p->state = RUNNABLE;
    n++;
  }
  return n;
}

// The group of that name and kind, or -1. System, Other and Utilities (slots 0 to 2) are never found.
int
group_find(char *name, int kind)
{
  int i, r = -1;

  acquire(&ptable.lock);
  for(i = 3; i < PS_MAXGROUP; i++)
    if(grouptab[i].used && grouptab[i].kind == kind && strncmp(grouptab[i].name, name, 16) == 0){
      r = i;
      break;
    }
  release(&ptable.lock);
  return r;
}

// 1 if the calling process is in the group of this name and kind. No lock: the caller is alive in its group, which keeps the slot from being reused.
int
proc_in_group(char *name, int kind)
{
  struct proc *p = myproc();
  int g;

  if(p == 0)
    return 0;
  g = p->gid;
  if(g < 3 || g >= PS_MAXGROUP || !grouptab[g].used || grouptab[g].kind != kind)
    return 0;
  return strncmp(grouptab[g].name, name, 16) == 0;
}

// 1 if the calling process is in an App or Agent group, and gives the group's name and kind. Groups 0 to 2 are System, Other and Utilities.
int
proc_group_name(char *name, int *kind)
{
  struct proc *p = myproc();
  int g;

  if(p == 0)
    return 0;
  g = p->gid;
  if(g < 3 || g >= PS_MAXGROUP || !grouptab[g].used)
    return 0;
  safestrcpy(name, grouptab[g].name, 16);
  *kind = grouptab[g].kind;
  return 1;
}

// Kill every process of group gid in one pass, and refuse new forks into it. Returns the number marked,
// -1 for no such group, -2 for System (init and the Owner live there). A process being forked at that
// moment can escape the pass: run it again if the group is still listed.
int
kill_group(int gid)
{
  int n;

  if(gid == 0)
    return -2;
  if(gid < 0 || gid >= PS_MAXGROUP)
    return -1;
  acquire(&ptable.lock);
  if(!grouptab[gid].used){
    release(&ptable.lock);
    return -1;
  }
  n = kill_group_locked(gid);
  release(&ptable.lock);
  return n;
}
