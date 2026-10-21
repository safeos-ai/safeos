#ifndef SAFEOS_PSINFO_H
#define SAFEOS_PSINFO_H
// Snapshot layout shared by pskernel.c (fills it) and psuser.c (prints it).

#include "param.h"
#include "resource.h"

#define PS_MAXPROC  NPROC
#define PS_MAXCPU   NCPU
#define PS_MAXPOL   RULE_MAX
#define PS_MAXPOOL  4
#define PS_MAXGROUP 16

#define GK_SYSTEM 0         // kinds of group
#define GK_APP    1
#define GK_AGENT  2
#define GK_UTILITY 3

#define PS_ROLE_SCHED   0
#define PS_ROLE_WORKER  1
#define PS_ROLE_BOTH    2     // single-CPU system: cpu0 schedules and runs

struct ps_group {
  int  id;
  char name[16];
  int  kind;                  // GK_*
  int  nproc;                 // live processes in the group
  int  cpu_ticks;             // CPU ticks used by its processes in the recent window
  int  mem_pages;             // pages held by its live processes
};

struct ps_cpu {
  int  role;
  int  pid;                   // process running now, 0 = none
  int  assigned_pid;          // handed over by cpu0, not started yet, 0 = none
  char name[16];              // name of the running process
};

struct ps_proc {
  int  pid;
  int  last_cpu;              // -1 = never ran
  int  age;                   // ticks since creation (uncalibrated)
  char state[12];
  char name[16];
  int  used[NRESOURCE];
  int  violations[NRESOURCE];
  int  gid;                    // the process group
  int  cpu_ticks;             // CPU ticks it used in the recent window
  int  mem_pages;             // kernel and user pages it holds now
};

struct psinfo {
  int  now;                   // tick count at snapshot time
  int  ncpu;
  int  nproc;
  int  npolicy;
  int  npool;
  int  ngroup;
  int  usage_window;           // ticks covered by the recent CPU figures
  int  usage_workers;          // CPUs that run processes: the capacity per tick
  char pool_name[PS_MAXPOOL][8];
  int  pool_free[PS_MAXPOOL];
  int  pool_total[PS_MAXPOOL];
  char res_name[NRESOURCE][12];
  char res_unit[NRESOURCE][8];
  struct ps_cpu      cpu[PS_MAXCPU];
  struct ps_proc     proc[PS_MAXPROC];
  struct policy_view policy[PS_MAXPOL];
  struct ps_group  group[PS_MAXGROUP];
  struct kind_rules kindrule[NKINDRULE];   // the limits per kind of group
};

#endif
