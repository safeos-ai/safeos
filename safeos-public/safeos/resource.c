// SafeOS resource quotas. Three separate pieces:
//   resources[]      facts about each resource type (name, kill message)
//   root_policy[]    configuration per program (limit, action, kill_after, scope)
//   counters         state: p->res per process, program_counters[] per program

#include "types.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"
#include "spinlock.h"
#include "resource.h"

// ---- resource types ----
struct resource_info {
  char *name;
  char *unit;                  // what one charge unit means, for reports
  char *kill_msg;
};

static struct resource_info resources[NRESOURCE] = {
  [RES_STDOUT]  = { "stdout",  "writes", "Exception: Run out of Resources" },
  [RES_CPUTIME] = { "cputime", "ticks",  "Exception: Run out of Time" },
};

// ---- Owner-Mode policy: a program not listed here is unlimited ----
static struct program_policy root_policy[RULE_MAX] = {
  { .progname = "hello",
    .limit  = { [RES_STDOUT] = 3 },
    .action = { [RES_STDOUT] = ACTION_KILL | ACTION_DENY }, // must deny to prevent the current write
    .scope  = { [RES_STDOUT] = SCOPE_PROGRAM } },
  { .progname = "deadloop",
    .limit  = { [RES_CPUTIME] = 50 },
    .action = { [RES_CPUTIME] = ACTION_KILL },
    .scope  = { [RES_CPUTIME] = SCOPE_PROCESS } },
  { .progname = "helloagain",
    .limit  = { [RES_STDOUT] = 1 },
    .action = { [RES_STDOUT] = ACTION_REPORT },
    .scope  = { [RES_STDOUT] = SCOPE_PROCESS } },
  { .progname = "deadloopagain",
    .limit  = { [RES_CPUTIME] = 500 },
    .action = { [RES_CPUTIME] = ACTION_KILL },
    .scope  = { [RES_CPUTIME] = SCOPE_PROGRAM } },
};
#define NPOLICY ((int)(sizeof(root_policy)/sizeof(root_policy[0])))

// ---- SCOPE_PROGRAM state: one counter, with its own lock, per (program, resource) ----
// A zero-filled spinlock is a valid unlocked lock, so no init call is needed.
struct counter {
  struct spinlock lock;
  int used;
  int violations;
  int over;                    // SCOPE_GROUP: 1 while the group is above its limit
  int run;                     // SCOPE_GROUP output: the writes of the current launch
  int pending;                 // SCOPE_GROUP output: the limit was just crossed and app_check has not stopped the group yet
};
static struct counter program_counters[NPOLICY][NRESOURCE];

static int
lookup_policy(char *name)
{
  int i;

  for(i = 0; i < NPOLICY; i++)
    if(root_policy[i].progname[0] != 0 &&
       strncmp(name, root_policy[i].progname, 16) == 0)
      return i;
  return -1;
}

// ---- actions ----
static void
action_to_report(struct proc *p, int which, int idx, int used, int limit)
{
  cprintf("[resource] pid=%d %s: %s used=%d limit=%d violation_num=%d\n",
          p->pid, p->name, resources[which].name, used, limit, idx + 1);
}

static void
action_to_kill(struct proc *p, int which)
{
  if(p->killed)
    return;                    // already dying: don't announce twice
  cprintf("%s\n", resources[which].kill_msg);
  p->killed = 1;               // trap() exits the process on its way back to user mode
}

// ---- an installed app's output limit, counted at every write ----
// The write path asks which App or Agent group the writer is in, finds that app's SCOPE_GROUP row, and counts the write in the
// row's own counter, under the counter's lock alone. The write that goes over the limit is refused when the row says deny, and
// is not counted, so the total stays at the limit. The first crossing is noted for app_check, which stops the group at the next
// tick. Returns -1 if the write must be refused.
static int
group_stdout_charge(struct proc *p, int amount)
{
  struct program_policy *pol;
  struct counter *c;
  char name[16];
  int pi, limit, action, newrun, over = 0;

  if(!group_app_name(p, name, sizeof(name)))
    return 0;
  pi = lookup_policy(name);
  if(pi < 0)
    return 0;
  pol = &root_policy[pi];
  limit = pol->limit[RES_STDOUT];
  if(pol->scope[RES_STDOUT] != SCOPE_GROUP || limit <= 0)
    return 0;
  action = pol->action[RES_STDOUT];
  c = &program_counters[pi][RES_STDOUT];
  acquire(&c->lock);
  newrun = c->run + amount;
  if(newrun > c->used)
    c->used = newrun;                // the highest figure reached: a refused write shows as limit + 1
  if(newrun > limit){
    over = 1;
    if(!c->over){
      c->over = 1;
      c->violations++;
      c->pending = 1;
    }
    if(!(action & ACTION_DENY))
      c->run = newrun;
  } else
    c->run = newrun;
  release(&c->lock);
  return (over && (action & ACTION_DENY)) ? -1 : 0;
}

// ---- mechanism ----
int
resource_charge(int which, struct proc *p, int amount)
{
  struct program_policy *pol;
  struct counter *c;
  int pi, limit, over, idx, usedsnap, action;

  // Accounting: every process is counted, with or without a policy.
  // Only the CPU running p touches p->res, so no lock is needed.
  p->res.used[which] += amount;
  if(which == RES_STDOUT && p->gid >= 3 && group_stdout_charge(p, amount) < 0)
    return -1;                 // an installed app's group is over its output limit: the write is refused

  pi = lookup_policy(p->name);
  if(pi < 0 || root_policy[pi].limit[which] == 0)
    return 0;                  // unlimited
  pol = &root_policy[pi];
  limit = pol->limit[which];
  if(pol->scope[which] == SCOPE_GROUP)
    return 0;                  // counted over the whole group by the group check in proc.c

  // Update counters first; report and kill only afterwards, with no lock held,
  // so cprintf never nests inside one of ours.
  if(pol->scope[which] == SCOPE_PROGRAM){
    c = &program_counters[pi][which];
    acquire(&c->lock);
    c->used += amount;
    usedsnap = c->used;
    over = usedsnap > limit;
    idx = over ? c->violations++ : 0;   // zero-based index of this violation
    release(&c->lock);
  } else {
    // Only the CPU running p charges its own counters: no lock needed.
    usedsnap = p->res.used[which];
    over = usedsnap > limit;
    idx = over ? p->res.violations[which]++ : 0;
  }

  if(!over)
    return 0;

  action = pol->action[which];
  if(action & ACTION_REPORT)
    action_to_report(p, which, idx, usedsnap, limit);
  if((action & ACTION_KILL) && idx >= pol->kill_after_index0[which])
    action_to_kill(p, which);
  return (action & ACTION_DENY) ? -1 : 0;
}

// Admission check, called by exec() before a new program image is committed.
// Returns -1 if the first charge of any resource would immediately kill the
// process, so the program is refused instead of started. Read-only: it charges
// nothing and kills nothing. Assumes the smallest charge is one unit.
int
resource_admit(struct proc *p, char *progname)
{
  struct program_policy *pol;
  struct counter *c;
  int pi, which, used, viol;
  char name[16];                    // same truncation exec applies to p->name

  safestrcpy(name, progname, sizeof(name));
  pi = lookup_policy(name);
  if(pi < 0)
    return 0;                       // no policy: unlimited
  pol = &root_policy[pi];

  for(which = 0; which < NRESOURCE; which++){
    if(pol->limit[which] == 0 || !(pol->action[which] & ACTION_KILL) || pol->scope[which] == SCOPE_GROUP)
      continue;
    if(pol->scope[which] == SCOPE_PROGRAM){
      c = &program_counters[pi][which];
      acquire(&c->lock);
      used = c->used;
      viol = c->violations;
      release(&c->lock);
    } else {
      used = p->res.used[which];    // counters survive exec, by our rule
      viol = p->res.violations[which];
    }
    // The next charge would be over the limit, and its violation index
    // (the current violation count) would trigger the kill.
    if(used + 1 > pol->limit[which] && viol >= pol->kill_after_index0[which]){
      cprintf("%s\n", resources[which].kill_msg);
      return -1;
    }
  }
  return 0;
}

// ---- read-only accessors, used by pskernel.c ----
char*
resource_name(int which)
{
  return resources[which].name;
}

char*
resource_unit(int which)
{
  return resources[which].unit;
}

// Copy policy row i (configuration plus shared counters) into *out.
// Returns -1 when i is past the last row. Each counter lock is taken alone
// and never nested, and nothing is written to *out while a lock is held.
int
resource_policy_view(int i, struct policy_view *out)
{
  struct program_policy *pol;
  struct counter *c;
  int row, seen = -1, which, u, v;

  if(i < 0)
    return -1;
  for(row = 0; row < NPOLICY; row++){      // the i-th row that is in use
    if(root_policy[row].progname[0] == 0)
      continue;
    if(++seen == i)
      break;
  }
  if(row >= NPOLICY)
    return -1;
  pol = &root_policy[row];
  safestrcpy(out->progname, pol->progname, sizeof(out->progname));
  for(which = 0; which < NRESOURCE; which++){
    out->limit[which] = pol->limit[which];
    out->action[which] = pol->action[which];
    out->kill_after_index0[which] = pol->kill_after_index0[which];
    out->scope[which] = pol->scope[which];
    c = &program_counters[row][which];
    acquire(&c->lock);
    u = c->used;
    v = c->violations;
    release(&c->lock);
    out->shared_used[which] = u;
    out->shared_violations[which] = v;
  }
  return 0;
}

// ---- rule editing, used by the Owner ----
// Plain stores, no lock: a reader on another CPU may see a half-changed row for
// about one tick. A row is claimed by writing its name last.

static struct program_policy saved_rules[RULE_MAX];   // the table as last loaded or saved

static void
counters_reset(int row)
{
  struct counter *c;
  int which;

  for(which = 0; which < NRESOURCE; which++){
    c = &program_counters[row][which];
    acquire(&c->lock);
    c->used = 0;
    c->violations = 0;
    c->over = 0;
    c->run = 0;
    c->pending = 0;
    release(&c->lock);
  }
}

static void
row_free(int row)
{
  int which;

  for(which = 0; which < NRESOURCE; which++){    // limits first: readers see "unlimited"
    root_policy[row].limit[which] = 0;
    root_policy[row].action[which] = 0;
  }
  memset(&root_policy[row], 0, sizeof(root_policy[row]));
  counters_reset(row);
}

int
rule_set(char *prog, int which, int limit, int action, int scope)
{
  struct program_policy *pol;
  int i, j, free = -1;

  if(prog[0] == 0 || strlen(prog) >= (int)sizeof(root_policy[0].progname) ||
     which < 0 || which >= NRESOURCE || limit < 0 || (action & ~7) != 0 ||
     (scope != SCOPE_PROCESS && scope != SCOPE_PROGRAM && scope != SCOPE_GROUP))
    return -1;
  if(limit == 0)
    action = 0;
  for(i = 0; i < NPOLICY; i++){
    if(root_policy[i].progname[0] == 0){
      if(free < 0)
        free = i;
    } else if(strncmp(prog, root_policy[i].progname, 16) == 0)
      break;
  }
  if(i == NPOLICY){                    // no row for this program yet
    if(limit == 0)
      return 0;                        // nothing to remove
    if(free < 0)
      return -2;                       // table full
    counters_reset(free);
    pol = &root_policy[free];
    memset(pol, 0, sizeof(*pol));
    pol->scope[which] = scope;
    pol->action[which] = action;
    pol->limit[which] = limit;
    safestrcpy(pol->progname, prog, sizeof(pol->progname));   // the name goes last
    return 0;
  }
  pol = &root_policy[i];
  pol->scope[which] = scope;
  pol->action[which] = action;
  pol->limit[which] = limit;
  for(j = 0; j < NRESOURCE; j++)
    if(pol->limit[j] != 0 || pol->action[j] != 0)
      return 0;
  row_free(i);                         // nothing left in this row
  return 0;
}

int
rule_remove(char *prog)
{
  int i;

  for(i = 0; i < NPOLICY; i++)
    if(root_policy[i].progname[0] != 0 &&
       strncmp(prog, root_policy[i].progname, 16) == 0){
      row_free(i);
      return 0;
    }
  return -1;
}

void
rules_export(struct program_policy *out)
{
  memmove(out, root_policy, sizeof(root_policy));
}

int
rules_import(struct program_policy *in)
{
  int i, j, which;

  // Check every row first: the table is replaced only if all of them are sane.
  for(i = 0; i < RULE_MAX; i++){
    if(in[i].progname[0] == 0)
      continue;
    for(j = 0; j < 16 && in[i].progname[j] != 0; j++)
      ;
    if(j == 16)
      return -1;                       // name not terminated
    if(strncmp(in[i].progname, "init", 16) == 0 ||
       strncmp(in[i].progname, "initcode", 16) == 0 ||
       strncmp(in[i].progname, "owner", 16) == 0)
      return -1;
    for(which = 0; which < NRESOURCE; which++){
      if(in[i].limit[which] < 0 || in[i].limit[which] > 1000000000 ||
         (in[i].action[which] & ~7) != 0 ||
         (in[i].scope[which] != SCOPE_PROCESS && in[i].scope[which] != SCOPE_PROGRAM && in[i].scope[which] != SCOPE_GROUP) ||
         in[i].kill_after_index0[which] < 0 || in[i].kill_after_index0[which] > 1000000)
        return -1;
    }
  }
  memmove(root_policy, in, sizeof(root_policy));
  for(i = 0; i < RULE_MAX; i++)
    counters_reset(i);
  return 0;
}

void
rules_snapshot(void)
{
  memmove(saved_rules, root_policy, sizeof(root_policy));
}

void
rules_restore(void)
{
  int i;

  memmove(root_policy, saved_rules, sizeof(root_policy));
  for(i = 0; i < RULE_MAX; i++)
    counters_reset(i);
}

int
rules_dirty(void)
{
  return memcmp(root_policy, saved_rules, sizeof(root_policy)) != 0;
}

// ---- the rows of installed apps ----
// A row named like an installed app is set by its manifest, so it is neither saved nor compared with the saved rules.
static int
row_is_app(struct program_policy *r, char (*names)[16], int n)
{
  int k;

  if(r->progname[0] == 0)
    return 0;
  for(k = 0; k < n; k++)
    if(strncmp(r->progname, names[k], 16) == 0)
      return 1;
  return 0;
}

void
rules_export_except(struct program_policy *out, char (*names)[16], int n)
{
  int i;

  memmove(out, root_policy, sizeof(root_policy));
  for(i = 0; i < NPOLICY; i++)
    if(row_is_app(&out[i], names, n))
      memset(&out[i], 0, sizeof(out[i]));
}

int
rules_dirty_except(char (*names)[16], int n)
{
  struct program_policy z, *a, *b;
  int i;

  memset(&z, 0, sizeof(z));
  for(i = 0; i < NPOLICY; i++){
    a = row_is_app(&root_policy[i], names, n) ? &z : &root_policy[i];
    b = row_is_app(&saved_rules[i], names, n) ? &z : &saved_rules[i];
    if(memcmp(a, b, sizeof(z)) != 0)
      return 1;
  }
  return 0;
}

void
rule_remove_saved(char *prog)          // take the program's row out of the saved copy
{
  int i;

  for(i = 0; i < NPOLICY; i++)
    if(saved_rules[i].progname[0] != 0 && strncmp(prog, saved_rules[i].progname, 16) == 0)
      memset(&saved_rules[i], 0, sizeof(saved_rules[i]));
}

// ---- SCOPE_GROUP rows: an installed app's own limits, counted over all the processes of its group in one launch ----
// Called from the group check in proc.c with ptable.lock held. The counter lock is taken alone and nothing is taken
// inside it. Returns the limit (0 = this group has no group row for that resource) and the row's action.
// used = the highest figure a launch has reached since boot; violations = how often the group crossed the limit since boot.
int
resource_group_check(char *name, int which, int *val, int *action, int *crossed)
{
  struct counter *c;
  int pi, limit;

  *crossed = 0;
  pi = lookup_policy(name);
  if(pi < 0 || root_policy[pi].scope[which] != SCOPE_GROUP)
    return 0;
  limit = root_policy[pi].limit[which];
  if(limit <= 0)
    return 0;
  *action = root_policy[pi].action[which];
  c = &program_counters[pi][which];
  acquire(&c->lock);
  if(which == RES_STDOUT){
    *val = c->used;                // output is counted at every write (group_stdout_charge): the figure that crossed
    if(c->pending){
      c->pending = 0;
      *crossed = 1;                // the write path found the group over its limit
    }
  } else {
    if(*val > c->used)
      c->used = *val;
    if(*val > limit){
      if(!c->over){
        c->over = 1;
        c->violations++;
        *crossed = 1;              // report once per crossing
      }
    } else
      c->over = 0;
  }
  release(&c->lock);
  return limit;
}

// A fresh launch of an app: the counts of its group rows start again. used and violations are kept. Called by group_exec
// with ptable.lock held; the counter lock is taken alone.
void
resource_group_launch(char *name)
{
  struct counter *c;
  int pi, which;

  pi = lookup_policy(name);
  if(pi < 0)
    return;
  for(which = 0; which < NRESOURCE; which++){
    if(root_policy[pi].scope[which] != SCOPE_GROUP)
      continue;
    c = &program_counters[pi][which];
    acquire(&c->lock);
    c->run = 0;
    c->over = 0;
    c->pending = 0;
    release(&c->lock);
  }
}
