// SafeOS limits per kind of group (App, Agent, Utilities): percent of the whole machine's CPU and memory.
// This file holds the table and its edits. The check runs in proc.c every USAGE_STEP ticks.
// System is never limited. Edits apply at once, with plain stores, like the program rules.
#include "types.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"
#include "spinlock.h"
#include "resource.h"
#include "psinfo.h"

// On by default: report a kind that uses more than 20% of the CPU, kill one that holds more than 10% of memory.
#define KR_DEFAULTS \
  [GK_APP]   = { { 20, 10, 10000, 10000 }, { ACTION_REPORT, ACTION_KILL, ACTION_KILL, ACTION_KILL } }, \
  [GK_AGENT] = { { 20, 10, 10000, 10000 }, { ACTION_REPORT, ACTION_KILL, ACTION_KILL, ACTION_KILL } }

static struct kind_rules kr[NKINDRULE]       = { KR_DEFAULTS };
static struct kind_rules kr_saved[NKINDRULE] = { KR_DEFAULTS };

static int
entry_sane(struct kind_rules *e)
{
  int w;

  for(w = 0; w < 4; w++){
    if(e->limit[w] < 0 || e->limit[w] > (w < 2 ? 100 : 1000000000))
      return 0;
    if(e->limit[w] == 0 && e->action[w] != 0)
      return 0;
    if(e->limit[w] > 0 && (e->action[w] == 0 || (e->action[w] & ~(ACTION_REPORT | ACTION_KILL)) != 0))
      return 0;
  }
  return 1;
}

int
kindrules_sane(struct kind_rules *in)
{
  int k;

  for(k = 0; k < NKINDRULE; k++){
    if(!entry_sane(&in[k]))
      return 0;
    if(k == GK_SYSTEM && (in[k].limit[0] != 0 || in[k].limit[1] != 0 || in[k].limit[2] != 0 || in[k].limit[3] != 0))
      return 0;
  }
  return 1;
}

int
kindrule_set(int kind, int which, int limit, int action)
{
  if(kind != GK_APP && kind != GK_AGENT && kind != GK_UTILITY)
    return -1;                               // System is never limited
  if(which < 0 || which > 3 || limit < 0 || limit > (which < 2 ? 100 : 1000000000))
    return -1;
  if(limit > 0 && (action == 0 || (action & ~(ACTION_REPORT | ACTION_KILL)) != 0))
    return -1;
  kr[kind].limit[which] = limit;
  kr[kind].action[which] = limit > 0 ? action : 0;
  return 0;
}

int
kindrule_get(int kind, int which, int *action)
{
  if(kind <= 0 || kind >= NKINDRULE || which < 0 || which > 3)
    return 0;
  if(action)
    *action = kr[kind].action[which];
  return kr[kind].limit[which];
}

void
kindrules_view(struct kind_rules *out)
{
  memmove(out, kr, sizeof(kr));
}

void
kindrules_export(struct kind_rules *out)
{
  memmove(out, kr, sizeof(kr));
}

int
kindrules_import(struct kind_rules *in)
{
  if(!kindrules_sane(in))
    return -1;
  memmove(kr, in, sizeof(kr));
  return 0;
}

void
kindrules_snapshot(void)
{
  memmove(kr_saved, kr, sizeof(kr));
}

void
kindrules_restore(void)
{
  memmove(kr, kr_saved, sizeof(kr));
}

int
kindrules_dirty(void)
{
  return memcmp(kr, kr_saved, sizeof(kr)) != 0;
}
