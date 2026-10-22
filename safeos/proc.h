#include "resource.h"
// Per-CPU state
struct cpu {
  uchar apicid;                // Local APIC ID
  struct context *scheduler;   // swtch() here to enter scheduler
  struct taskstate ts;         // Used by x86 to find stack for interrupt
  struct segdesc gdt[NSEGS];   // x86 global descriptor table
  volatile uint started;       // Has the CPU started?
  int ncli;                    // Depth of pushcli nesting.
  int intena;                  // Were interrupts enabled before pushcli?
  struct proc *proc;           // The process running on this cpu or null
  int scheduler_announced_dump;
  struct proc *volatile assigned;       // process the GSC handed this worker (0 = none)
  volatile int idle;           // worker sets 1 when ready for new work
  int scheduler_announced;
};

extern struct cpu cpus[NCPU];
extern int ncpu;

//PAGEBREAK: 17
// Saved registers for kernel context switches.
// Don't need to save all the segment registers (%cs, etc),
// because they are constant across kernel contexts.
// Don't need to save %eax, %ecx, %edx, because the
// x86 convention is that the caller has saved them.
// Contexts are stored at the bottom of the stack they
// describe; the stack pointer is the address of the context.
// The layout of the context matches the layout of the stack in swtch.S
// at the "Switch stacks" comment. Switch doesn't save eip explicitly,
// but it is on the stack and allocproc() manipulates it.
struct context {
  uint edi;
  uint esi;
  uint ebx;
  uint ebp;
  uint eip;
};

enum procstate { UNUSED, EMBRYO, SLEEPING, RUNNABLE, RUNNING, ZOMBIE,
                  ASSIGNED };  // SafeOS: handed to a worker by the GSC, not yet running

// Per-process state
struct proc {
  uint sz;                     // Size of process memory (bytes)
  pde_t* pgdir;                // Page table
  char *kstack;                // Bottom of kernel stack for this process
  enum procstate state;        // Process state
  int pid;                     // Process ID
  struct proc *parent;         // Parent process
  struct trapframe *tf;        // Trap frame for current syscall
  struct context *context;     // swtch() here to run process
  void *chan;                  // If non-zero, sleeping on chan
  int killed;                  // If non-zero, have been killed
  struct file *ofile[NOFILE];  // Open files
  struct inode *cwd;           // Current directory
  char name[16];               // Process name (debugging)
  int last_cpu;                 // which CPU last ran this process
  int kproc;                   // 1 = kernel-only process (the Owner): no user space, cannot be killed
  int gid;                      // process group (see the groups at the end of proc.c); 0 = System
  uint ucpu;                    // ticks this process was seen running at cpu0's tick: the usage columns use it
  uint qtick;                    // the last tick this process was charged CPU quota in: at most one charge per tick
  uchar fpu[108];               // saved x87 state (fnsave image), saved and cleared on every switch-out
  struct proc_res res;          // SafeOS per-process resource counters
};

// Process memory is laid out contiguously, low addresses first:
//   text
//   original data and bss
//   fixed-size stack
//   expandable heap

#define USAGE_STEP 10   // CPU totals are sampled every USAGE_STEP ticks
#define USAGE_RING 101    // so the recent window is about USAGE_STEP * (USAGE_RING - 1) ticks
