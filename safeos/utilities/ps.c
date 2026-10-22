// ps: print the SafeOS report from the kernel's snapshot.
// All output is collected in a buffer and sent with write(), so the report
// reaches the console as one block (see OUTCHUNK for the size limit).
#include "types.h"
#include "stat.h"
#include "user.h"
#include "psinfo.h"

#define LINEMAX  159
#define OUTCHUNK 1536    // largest write the console path keeps in one piece

static struct psinfo info;     // static: the user stack is one page
static char line[LINEMAX + 1];
static int llen;
static char out[OUTCHUNK];
static int olen;

static void
oflush(void)
{
  if(olen > 0)
    write(1, out, olen);
  olen = 0;
}

// Append one finished line to the output buffer. If it would not fit, send
// what we have first, so a break always falls between lines.
static void
oline(char *s)
{
  int n = strlen(s);

  if(olen + n + 1 > OUTCHUNK)
    oflush();
  memmove(out + olen, s, n);
  olen += n;
  out[olen++] = '\n';
}

static void
lstart(void)
{
  llen = 0;
  line[0] = 0;
}

static void
lend(void)
{
  oline(line);
}

// Pad the current line with spaces so the text added since 'start' is 'width' wide.
static void
lpad(int start, int width)
{
  while(llen - start < width && llen < LINEMAX)
    line[llen++] = ' ';
  line[llen] = 0;
}

static void
lstr(char *s, int width)
{
  int start = llen;

  while(*s && llen < LINEMAX)
    line[llen++] = *s++;
  lpad(start, width);
}

static void
lint(int v, int width)
{
  char tmp[12], s[12];
  int i = 0, j = 0;
  uint x = v < 0 ? -v : v;

  do{
    tmp[i++] = '0' + x % 10;
  }while((x /= 10) != 0);
  if(v < 0)
    s[j++] = '-';
  while(i > 0)
    s[j++] = tmp[--i];
  s[j] = 0;
  lstr(s, width);
}

static void
laction(int a, int width)
{
  int start = llen;
  int first = 1;

  if(a == 0){
    lstr("none", 0);
  } else {
    if(a & ACTION_REPORT){
      lstr("report", 0);
      first = 0;
    }
    if(a & ACTION_KILL){
      if(!first)
        lstr("+", 0);
      lstr("kill", 0);
      first = 0;
    }
    if(a & ACTION_DENY){
      if(!first)
        lstr("+", 0);
      lstr("deny", 0);
    }
  }
  lpad(start, width);
}

static struct policy_view*
find_policy(char *name)
{
  int i;

  for(i = 0; i < info.npolicy; i++)
    if(strcmp(info.policy[i].progname, name) == 0)
      return &info.policy[i];
  return 0;
}

int
main(void)
{
  int i, r, start;
  struct ps_proc *pr;
  struct ps_cpu *pc;
  struct policy_view *pv;

  if(ps(&info) < 0){
    printf(2, "ps: snapshot failed\n");
    exit();
  }

  lstart();
  lstr("SafeOS report: tick ", 0);
  lint(info.now, 0);
  lstr(", ", 0);
  lint(info.ncpu, 0);
  lstr(" cpu(s)", 0);
  lend();
  oline("");

  // ---- CPUs ----
  oline("CPUS");
  lstart();
  lstr("CPU", 5);
  lstr("ROLE", 15);
  lstr("NOW", 0);
  lend();
  for(i = 0; i < info.ncpu; i++){
    pc = &info.cpu[i];
    lstart();
    lint(i, 5);
    lstr(pc->role == PS_ROLE_SCHED ? "scheduler" :
         pc->role == PS_ROLE_BOTH ? "sched+worker" : "worker", 15);
    if(pc->pid){
      lstr("pid ", 0);
      lint(pc->pid, 0);
      lstr(" ", 0);
      lstr(pc->name, 0);
    } else if(pc->assigned_pid){
      lstr("assigned pid ", 0);
      lint(pc->assigned_pid, 0);
      lstr(" (not started)", 0);
    } else {
      lstr(pc->role == PS_ROLE_WORKER ? "idle" : "-", 0);
    }
    lend();
  }

  // ---- processes ----
  oline("");
  oline("PROCESSES");
  lstart();
  lstr("PID", 8);
  lstr("STATE", 10);
  lstr("CPU", 5);
  lstr("AGE", 8);
  lstr("NAME", 16);
  for(r = 0; r < NRESOURCE; r++)
    lstr(info.res_name[r], 14);
  lend();
  for(i = 0; i < info.nproc; i++){
    pr = &info.proc[i];
    pv = find_policy(pr->name);
    lstart();
    lint(pr->pid, 8);
    lstr(pr->state, 10);
    if(pr->last_cpu < 0)
      lstr("-", 5);
    else
      lint(pr->last_cpu, 5);
    lint(pr->age, 8);
    lstr(pr->name, 16);
    for(r = 0; r < NRESOURCE; r++){
      start = llen;
      lint(pr->used[r], 0);
      if(pv && pv->limit[r] > 0){
        if(pv->scope[r] == SCOPE_PROCESS){
          lstr("/", 0);
          lint(pv->limit[r], 0);
        } else {
          lstr("*(", 0);
          lint(pv->shared_used[r], 0);
          lstr(")", 0);
        }
      }
      if(pr->violations[r] > 0)
        lstr("!", 0);
      lpad(start, 14);
    }
    lend();
  }
  lstart();
  lstr("units: age=ticks", 0);
  for(r = 0; r < NRESOURCE; r++){
    lstr("  ", 0);
    lstr(info.res_name[r], 0);
    lstr("=", 0);
    lstr(info.res_unit[r], 0);
  }
  lend();
  oline("       /N = per-process limit   *(T) = shared program limit, T = program total   ! = over limit");

  // ---- policy ----
  oline("");
  oline("POLICY (Owner-Mode)");
  lstart();
  lstr("PROGRAM", 16);
  lstr("RESOURCE", 10);
  lstr("LIMIT", 7);
  lstr("SCOPE", 9);
  lstr("ACTION", 18);
  lstr("KILL#", 7);
  lstr("SHARED", 0);
  lend();
  for(i = 0; i < info.npolicy; i++){
    pv = &info.policy[i];
    for(r = 0; r < NRESOURCE; r++){
      if(pv->limit[r] == 0)
        continue;
      lstart();
      lstr(pv->progname, 16);
      lstr(info.res_name[r], 10);
      lint(pv->limit[r], 7);
      lstr(pv->scope[r] == SCOPE_PROGRAM ? "program" : pv->scope[r] == SCOPE_GROUP ? "group" : "process", 9);
      laction(pv->action[r], 18);
      if(pv->action[r] & ACTION_KILL)
        lint(pv->kill_after_index0[r] + 1, 7);
      else
        lstr("-", 7);
      if(pv->scope[r] == SCOPE_PROGRAM || pv->scope[r] == SCOPE_GROUP){
        lint(pv->shared_used[r], 0);
        lstr(" used, ", 0);
        lint(pv->shared_violations[r], 0);
        lstr(" violation(s)", 0);
      } else {
        lstr("-", 0);
      }
      lend();
    }
  }
  oline("KILL# = the violation number that kills the process");

  // ---- memory pools ----
  oline("");
  oline("MEMORY POOLS (4 KB pages)");
  lstart();
  lstr("POOL", 10);
  lstr("FREE", 10);
  lstr("USED", 10);
  lstr("TOTAL", 0);
  lend();
  for(i = 0; i < info.npool; i++){
    lstart();
    lstr(info.pool_name[i], 10);
    lint(info.pool_free[i], 10);
    lint(info.pool_total[i] - info.pool_free[i], 10);
    lint(info.pool_total[i], 0);
    lend();
  }
  oline("(pool figures include this ps process itself)");

  oflush();
  exit();
}
