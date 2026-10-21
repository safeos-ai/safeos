// SafeOS report, kernel side: snapshot the system into a user buffer.
// Nothing is printed here, so no console lock is taken while ptable.lock is
// held. psuser.c formats and prints.

#include "types.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"
#include "spinlock.h"
#include "resource.h"
#include "mempool.h"
#include "psinfo.h"

// Must match the definition in proc.c exactly (a mismatch compiles silently).
extern struct {
  struct spinlock lock;
  struct proc proc[NPROC];
} ptable;

static char *state_name[] = {
  [UNUSED]    "unused",
  [EMBRYO]    "embryo",
  [SLEEPING]  "sleeping",
  [RUNNABLE]  "runnable",
  [RUNNING]   "running",
  [ZOMBIE]    "zombie",
  [ASSIGNED]  "assigned",
};

extern void group_fill_locked(struct psinfo *out);   // proc.c: fills out->group; the caller holds ptable.lock

extern int proc_cpu_recent(struct proc *p);   // proc.c
extern int proc_mem_pages(struct proc *p);    // proc.c

int
ps_snapshot(struct psinfo *out)
{
  struct ps_proc *r;
  struct proc *p;
  struct cpu *c;
  int i, n, st;

  memset(out, 0, sizeof(*out));

  // One lock hold gives a consistent snapshot of processes and CPUs.
  acquire(&ptable.lock);
  out->now = ticks;
  n = 0;
  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
    if(p->state == UNUSED)
      continue;
    r = &out->proc[n++];
    r->pid = p->pid;
    r->last_cpu = p->last_cpu;
    r->age = (int)(ticks - p->res.start_tick);
    r->gid = p->gid;
    r->cpu_ticks = proc_cpu_recent(p);
    r->mem_pages = proc_mem_pages(p);
    st = p->state;
    safestrcpy(r->state,
               (st >= 0 && st < NELEM(state_name) && state_name[st]) ? state_name[st] : "?",
               sizeof(r->state));
    safestrcpy(r->name, p->name, sizeof(r->name));
    for(i = 0; i < NRESOURCE; i++){
      r->used[i] = p->res.used[i];
      r->violations[i] = p->res.violations[i];
    }
  }
  out->nproc = n;

  out->ncpu = ncpu;
  for(i = 0; i < ncpu && i < PS_MAXCPU; i++){
    c = &cpus[i];
    out->cpu[i].role = (ncpu == 1) ? PS_ROLE_BOTH :
                       (i == 0) ? PS_ROLE_SCHED : PS_ROLE_WORKER;
    if(c->proc){
      out->cpu[i].pid = c->proc->pid;
      safestrcpy(out->cpu[i].name, c->proc->name, sizeof(out->cpu[i].name));
    }
    if(c->assigned)
      out->cpu[i].assigned_pid = c->assigned->pid;
  }
  group_fill_locked(out);
  kindrules_view(out->kindrule);
  release(&ptable.lock);

  // Resource and policy data come after the release: the policy view takes
  // its own counter locks, and the rule is that no two locks are ever nested.
  for(i = 0; i < NRESOURCE; i++){
    safestrcpy(out->res_name[i], resource_name(i), sizeof(out->res_name[i]));
    safestrcpy(out->res_unit[i], resource_unit(i), sizeof(out->res_unit[i]));
  }
  for(i = 0; i < PS_MAXPOL; i++)
    if(resource_policy_view(i, &out->policy[i]) < 0)
      break;
  out->npolicy = i;

  // Pool occupancy, read after ptable.lock is released.
  for(i = 0; i < PS_MAXPOOL; i++)
    if(pool_info(i, out->pool_name[i], sizeof(out->pool_name[i]),
                 &out->pool_free[i], &out->pool_total[i]) < 0)
      break;
  out->npool = i;
  return 0;
}

int
sys_ps(void)
{
  struct psinfo *out;

  if(argptr(0, (char**)&out, sizeof(*out)) < 0)
    return -1;
  return ps_snapshot(out);
}
