// The Owner at Ring 1 (step 3b-ii): login and the read-only commands. It runs with its own
// segments and calls the kernel only through gate 65. It includes only the kernel's type
// and layout definitions and pure code (SHA-256 and the passphrase check).
#include "types.h"
#include "rootblock.h"
#include "sha256.h"
#include "rootpass.h"
#include "psinfo.h"

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
static void reg_status_line(void) __attribute__((unused));

#define STACK_TOP  0x00100000   // OWNER1_STACK_TOP in rootowner.h
#define POOL_BASE  0x10000000   // OWNER1_POOL_BASE in mempool.h
#define POOL_END   0x12000000   // POOL_BASE + 32 MB
#define PGSZ       4096

#define IDLE_SECS  60           // a session with no key for this long closes itself
#define IDLE_TICKS 60000        // backstop if the clock cannot be read

typedef __builtin_va_list va_list;
#define va_start(v, l) __builtin_va_start(v, l)
#define va_arg(v, t)   __builtin_va_arg(v, t)
#define va_end(v)      __builtin_va_end(v)

static inline int
gate(int op, uint a, uint b)
{
  int r;

  asm volatile("int $65" : "=a"(r) : "a"(op), "b"(a), "c"(b) : "memory");
  return r;
}

// ---- output: formatted here, sent with one call ----

static char obuf[256];
static int olen;
static struct rootblock *rb;    // the Owner block, in a page of the Owner pool
static struct psinfo snap;      // the kernel's snapshot, filled by SVC_SNAPSHOT

static void
oflush(void)
{
  if(olen > 0){
    gate(SVC_PRINT, (uint)obuf, olen);
    olen = 0;
  }
}

static void
oputc(int c)
{
  if(olen >= 255)
    oflush();
  obuf[olen++] = c;
}

static void
oputs(const char *s)
{
  while(*s)
    oputc(*s++);
}

static int
slen(const char *s)
{
  int n = 0;

  while(s[n])
    n++;
  return n;
}

static void
opad(const char *s, int w)        // a string, padded with spaces to width w
{
  int n = slen(s);

  oputs(s);
  for(; n < w; n++)
    oputc(' ');
}

static void
onum(int v, int base, int sign)
{
  static const char digits[] = "0123456789abcdef";
  char tmp[12];
  uint x;
  int i = 0, neg = 0;

  if(sign && v < 0){
    neg = 1;
    x = -v;
  } else
    x = v;
  do{
    tmp[i++] = digits[x % base];
    x /= base;
  }while(x > 0);
  if(neg)
    oputc('-');
  while(--i >= 0)
    oputc(tmp[i]);
}

static void
onumw(int v, int w)               // a decimal number, padded with spaces to width w
{
  char out[14];
  int i = 0, j = 0;
  uint u = v < 0 ? -v : v;
  char tmp[12];

  do{
    tmp[i++] = '0' + u % 10;
    u /= 10;
  }while(u > 0);
  if(v < 0)
    out[j++] = '-';
  while(i > 0)
    out[j++] = tmp[--i];
  out[j] = 0;
  opad(out, w);
}

static void
oprintf(const char *fmt, ...)
{
  va_list ap;
  const char *s;
  int c;

  va_start(ap, fmt);
  for(; (c = *fmt) != 0; fmt++){
    if(c != '%'){
      oputc(c);
      continue;
    }
    c = *++fmt;
    if(c == 0)
      break;
    switch(c){
    case 'd':
      onum(va_arg(ap, int), 10, 1);
      break;
    case 'x':
      onum(va_arg(ap, int), 16, 0);
      break;
    case 's':
      s = va_arg(ap, const char*);
      if(s == 0)
        s = "(null)";
      while(*s)
        oputc(*s++);
      break;
    case 'c':
      oputc(va_arg(ap, int));
      break;
    case '%':
      oputc('%');
      break;
    default:
      oputc('%');
      oputc(c);
      break;
    }
  }
  va_end(ap);
  oflush();
}

// ---- input: one line from the session keyboard ----
// mask: echo '*' instead of the typed characters.
// Returns the length, -1 after the idle limit, or -2 if the Owner pressed Ctrl-].
static int
readline(char *buf, int max, int mask)
{
  int n = 0, c, s, last, idle = 0, polls = 0;

  last = gate(SVC_RTC, 0, 0);
  for(;;){
    c = gate(SVC_GETC, 0, 0);
    if(c < 0){
      s = gate(SVC_RTC, 0, 0);
      if(s >= 0 && s != last){
        last = s;
        if(++idle >= IDLE_SECS)
          return -1;
      }
      if(++polls >= IDLE_TICKS)
        return -1;
      continue;
    }
    idle = polls = 0;
    if(c == 0x1D)
      return -2;
    if(c == '\r' || c == '\n'){
      buf[n] = 0;
      gate(SVC_PUTC, '\n', 0);
      return n;
    }
    if(c == '\b' || c == 0x7F){
      if(n > 0){
        n--;
        gate(SVC_PUTC, '\b', 0);
      }
      continue;
    }
    if(c >= 32 && c < 127 && n < max - 1){
      buf[n++] = c;
      gate(SVC_PUTC, mask ? '*' : c, 0);
    }
  }
}

// ---- login ----

static int
load_block(void)                 // 1 if a valid Owner block was read into rb
{
  if(rb == 0){
    rb = (struct rootblock*)gate(SVC_PAGE_ALLOC, 0, 0);
    if(rb == 0)
      return 0;
  }
  if(gate(SVC_READ_BLOCK, (uint)rb, 0) != 0)
    return 0;
  return rootblock_check(rb) == ROOTBLOCK_OK;
}

static int
login(void)
{
  char p[ROOT_PASS_MAX + 1];
  int tries, n, i, ok = 0;

  for(tries = 0; tries < 3 && !ok; tries++){
    oprintf("Owner passphrase: ");
    n = readline(p, sizeof(p), 1);
    if(n < 0)
      break;
    if(root_pass_verify(rb, p, n))
      ok = 1;
    else
      oprintf("Wrong passphrase.\n");
  }
  for(i = 0; i <= ROOT_PASS_MAX; i++)
    p[i] = 0;
  return ok;
}

// ---- commands ----

static int
is(char *line, char *word)
{
  int n = 0;

  while(word[n]){
    if(line[n] != word[n])
      return 0;
    n++;
  }
  return line[n] == 0 || line[n] == ' ';
}

static int
clamp(int n, int max)
{
  return n < 0 ? 0 : (n > max ? max : n);
}

static int
copy(char *dst, const char *src)
{
  int n = 0;

  while((dst[n] = src[n]) != 0)
    n++;
  return n;
}

static char*
action_str(int a, char *buf)
{
  int n = 0;

  buf[0] = 0;
  if(a & ACTION_REPORT)
    n += copy(buf + n, "report");
  if(a & ACTION_KILL){
    if(n)
      buf[n++] = '+';
    n += copy(buf + n, "kill");
  }
  if(a & ACTION_DENY){
    if(n)
      buf[n++] = '+';
    n += copy(buf + n, "deny");
  }
  if(n == 0)
    copy(buf, "count");
  return buf;
}

static char*
kernel_name(uint k)
{
  return k == ROOT_KERNEL_SAFEOS ? "SafeOS" : "xv6";
}

static char*
stage_name(uint s)
{
  if(s == ROOT_STAGE_NONE)
    return "none";
  if(s == ROOT_STAGE_HANDOVER)
    return "handover";
  if(s == ROOT_STAGE_CONFIRMED)
    return "confirmed";
  return "?";
}

static int
take_snapshot(void)              // 1 if the kernel filled snap
{
  if(gate(SVC_SNAPSHOT, (uint)&snap, sizeof(snap)) != 0){
    oprintf("the snapshot failed\n");
    return 0;
  }
  return 1;
}

static void
cmd_status(void)
{
  struct ps_cpu *c;
  char *rn;
  int i, n;

  if(!take_snapshot())
    return;
  oprintf("tick %d, %d cpu(s), %d process(es)\n", snap.now, snap.ncpu, snap.nproc);
  n = clamp(snap.ncpu, PS_MAXCPU);
  for(i = 0; i < n; i++){
    c = &snap.cpu[i];
    rn = c->role == PS_ROLE_SCHED ? "scheduler" :
         (c->role == PS_ROLE_WORKER ? "worker" : "sched+worker");
    oprintf("cpu%d  ", i);
    opad(rn, 14);
    if(c->role == PS_ROLE_SCHED)
      oprintf("-\n");
    else if(c->pid)
      oprintf("pid %d %s\n", c->pid, c->name);
    else
      oprintf("idle\n");
  }
  n = clamp(snap.npool, PS_MAXPOOL);
  for(i = 0; i < n; i++)
    oprintf("pool %s: %d of %d pages in use\n", snap.pool_name[i],
            snap.pool_total[i] - snap.pool_free[i], snap.pool_total[i]);
  reg_status_line();
  oprintf("Owner block (as of login): next boot %s, last hand-over stage %s, failed trials %d\n",
          kernel_name(rb->chosen), stage_name(rb->stage), rb->failures);
}

static int
eq16(const char *a, const char *b)       // two names equal, comparing at most 16 characters
{
  int i;

  for(i = 0; i < 16; i++){
    if(a[i] != b[i])
      return 0;
    if(a[i] == 0)
      return 1;
  }
  return 1;
}

static int
ieq(const char *a, const char *b)        // equal, ignoring the case of ASCII letters
{
  char x, y;

  for(;; a++, b++){
    x = *a;
    y = *b;
    if(x >= 'A' && x <= 'Z')
      x += 'a' - 'A';
    if(y >= 'A' && y <= 'Z')
      y += 'a' - 'A';
    if(x != y)
      return 0;
    if(x == 0)
      return 1;
  }
}

static char*
kind_name(int k)
{
  return k == GK_SYSTEM ? "System" : (k == GK_UTILITY ? "Utilities" : (k == GK_APP ? "App" : "Agent"));
}

static int
parse_kind(char *s)                       // System, Utilities, App or Agent in any case; -1 if s is not a kind
{
  if(ieq(s, "system"))
    return GK_SYSTEM;
  if(ieq(s, "utilities"))
    return GK_UTILITY;
  if(ieq(s, "app"))
    return GK_APP;
  if(ieq(s, "agent"))
    return GK_AGENT;
  return -1;
}

static int
find_group(char *name)                    // index of the group with this name in the snapshot, or -1
{
  int i, n = clamp(snap.ngroup, PS_MAXGROUP);

  for(i = 0; i < n; i++)
    if(eq16(snap.group[i].name, name))
      return i;
  return -1;
}

static int
kind_of_gid(int gid)                      // the kind of a group in the snapshot, or -1
{
  int i, n = clamp(snap.ngroup, PS_MAXGROUP);

  for(i = 0; i < n; i++)
    if(snap.group[i].id == gid)
      return snap.group[i].kind;
  return -1;
}

static int
pct10(int num, int den)       // num/den as tenths of a percent, rounded to the nearest tenth
{
  return den > 0 ? (num * 1000 + den / 2) / den : 0;
}

static void
opct(int tenths, int width)               // tenths of a percent as N.N%, padded to width
{
  char b[16], t[12];
  int i = 0, n = 0, v;

  if(tenths < 0)
    tenths = 0;
  v = tenths / 10;
  if(v == 0)
    t[i++] = '0';
  while(v > 0){
    t[i++] = '0' + v % 10;
    v /= 10;
  }
  while(i > 0)
    b[n++] = t[--i];
  b[n++] = '.';
  b[n++] = '0' + tenths % 10;
  b[n++] = '%';
  b[n] = 0;
  opad(b, width);
}

static int
pool_totals(int *used, int *own)          // all pool pages; the pages in use, and the Owner pool's share
{
  int i, k = clamp(snap.npool, PS_MAXPOOL), total = 0;

  *used = 0;
  *own = 0;
  for(i = 0; i < k; i++){
    total += snap.pool_total[i];
    *used += snap.pool_total[i] - snap.pool_free[i];
    if(eq16(snap.pool_name[i], "owner"))
      *own = snap.pool_total[i] - snap.pool_free[i];
  }
  return total;
}

static void
print_procs(int kind, int gid)            // a kind or gid of -1 means any
{
  struct ps_proc *p;
  int i, r, v, n, shown = 0, cap, total, used, own, ct, mt;
  int bestc = 0, bestm = 0, pidc = 0, pidm = 0;
  char *namec = "", *namem = "";

  total = pool_totals(&used, &own);
  cap = snap.usage_window * snap.usage_workers;
  opad("PID", 8);
  opad("STATE", 10);
  opad("CPU", 5);
  opad("AGE", 8);
  opad("NAME", 16);
  opad("CPU%", 8);
  opad("MEM%", 8);
  for(r = 0; r < NRESOURCE; r++)
    opad(snap.res_name[r], 10);
  oprintf("VIOL\n");
  n = clamp(snap.nproc, PS_MAXPROC);
  for(i = 0; i < n; i++){
    p = &snap.proc[i];
    if(gid >= 0 && p->gid != gid)
      continue;
    if(kind >= 0 && kind_of_gid(p->gid) != kind)
      continue;
    if((gid >= 0 || kind >= 0) && (is(p->state, "zombie") || is(p->state, "embryo")))
      continue;                         // only plain procs shows exited processes and ones still being created
    ct = pct10(p->cpu_ticks, cap);
    if(ct > 1000)
      ct = 1000;
    mt = pct10(p->mem_pages, total);
    onumw(p->pid, 8);
    opad(p->state, 10);
    onumw(p->last_cpu, 5);
    onumw(p->age, 8);
    opad(p->name, 16);
    opct(ct, 8);
    opct(mt, 8);
    v = 0;
    for(r = 0; r < NRESOURCE; r++){
      onumw(p->used[r], 10);
      v += p->violations[r];
    }
    onumw(v, 0);
    oputc('\n');
    shown++;
    if(ct > bestc){
      bestc = ct;
      pidc = p->pid;
      namec = p->name;
    }
    if(mt > bestm){
      bestm = mt;
      pidm = p->pid;
      namem = p->name;
    }
  }
  if(shown > 0 && (bestc > 0 || bestm > 0)){
    oprintf("heaviest:");
    if(bestc > 0){
      oprintf("  CPU pid %d %s ", pidc, namec);
      opct(bestc, 0);
    }
    if(bestm > 0){
      oprintf("  memory pid %d %s ", pidm, namem);
      opct(bestm, 0);
    }
    oputc('\n');
  }
  oflush();
}

static void
cmd_procs(char *arg)
{
  if(*arg){
    oprintf("procs takes no argument: use procskind <kind> or procsgroup <group>\n");
    return;
  }
  if(!take_snapshot())
    return;
  print_procs(-1, -1);
}

static void
cmd_procskind(char *arg)
{
  int k = parse_kind(arg);

  if(k < 0){
    oprintf("usage: procskind <kind>   kinds: System  Utilities  App  Agent\n");
    return;
  }
  if(!take_snapshot())
    return;
  print_procs(k, -1);
}

static void
cmd_procsgroup(char *arg)
{
  int g;

  if(*arg == 0){
    oprintf("usage: procsgroup <group>   (type groups)\n");
    return;
  }
  if(parse_kind(arg) >= 0){
    oprintf("%s is a kind, not a group; use procskind %s\n", arg, arg);
    return;
  }
  if(!take_snapshot())
    return;
  g = find_group(arg);
  if(g < 0){
    oprintf("no group named %s; type groups\n", arg);
    return;
  }
  print_procs(-1, snap.group[g].id);
}

static void
cmd_groups(void)
{
  int i, n, k, cap, used, total, own, t, mem = 0, csum = 0, msum = 0;
  int ct[PS_MAXGROUP], mt[PS_MAXGROUP];

  if(!take_snapshot())
    return;
  n = clamp(snap.ngroup, PS_MAXGROUP);
  total = pool_totals(&used, &own);
  cap = snap.usage_window * snap.usage_workers;
  for(i = 0; i < n; i++)
    mem += snap.group[i].mem_pages + (snap.group[i].kind == GK_SYSTEM ? own : 0);
  for(i = 0; i < n; i++){
    k = snap.group[i].kind;
    ct[i] = pct10(snap.group[i].cpu_ticks, cap);
    t = snap.group[i].mem_pages;
    if(k == GK_SYSTEM){
      t += own;                           // the Owner's pool
      if(used > mem)
        t += used - mem;                  // pages in use that no process owns (the kernel's own tables) are System's too
    }
    mt[i] = pct10(t, total);
    csum += ct[i];
    msum += mt[i];
  }
  if(csum > 1000)
    csum = 1000;
  if(msum > 1000)
    msum = 1000;
  oprintf("recent %d ticks   CPU busy ", snap.usage_window);
  opct(csum, 0);
  oprintf("   memory used ");
  opct(msum, 0);
  oputc('\n');
  opad("GROUP", 14);
  opad("KIND", 11);
  opad("PROCS", 7);
  opad("CPU", 9);
  oprintf("MEMORY\n");
  for(i = 0; i < n; i++){
    k = snap.group[i].kind;
    opad((k == GK_SYSTEM || k == GK_UTILITY) ? "-" : snap.group[i].name, 14);
    opad(kind_name(k), 11);
    onumw(snap.group[i].nproc, 7);
    opct(ct[i], 9);
    opct(mt[i], 0);
    oputc('\n');
  }
  opad("(unused)", 14);                   // idle CPU and free memory: the rest of each column, so both add up to 100%
  opad("", 11);
  opad("", 7);
  opct(1000 - csum, 9);
  opct(1000 - msum, 0);
  oputc('\n');
  oflush();
}

static void
cmd_mem(void)
{
  int i, n;

  if(!take_snapshot())
    return;
  opad("POOL", 10);
  opad("FREE", 10);
  opad("USED", 10);
  oprintf("TOTAL\n");
  n = clamp(snap.npool, PS_MAXPOOL);
  for(i = 0; i < n; i++){
    opad(snap.pool_name[i], 10);
    onumw(snap.pool_free[i], 10);
    onumw(snap.pool_total[i] - snap.pool_free[i], 10);
    onumw(snap.pool_total[i], 0);
    oputc('\n');
  }
  oflush();
}

static int same(const char *a, const char *b);

static int
prog_has_rules(char *only)           // 1 if the program has at least one rule
{
  struct policy_view *v;
  int i, r, n = clamp(snap.npolicy, PS_MAXPOL);

  for(i = 0; i < n; i++){
    v = &snap.policy[i];
    if(!same(v->progname, only))
      continue;
    for(r = 0; r < NRESOURCE; r++)
      if(v->limit[r] != 0 || v->action[r] != 0)
        return 1;
  }
  return 0;
}

static void
rules_show(char *only)               // the program rules: all of them, or only one program's (only = its name)
{
  struct policy_view *v;
  char ab[20];
  int i, r, n;

  if(!take_snapshot())
    return;
  n = clamp(snap.npolicy, PS_MAXPOL);
  if(only == 0 && n == 0){
    oprintf("no rules\n");
    return;
  }
  if(only != 0 && !prog_has_rules(only)){
    oprintf("no rules for %s\n", only);
    return;
  }
  opad("PROGRAM", 16);
  opad("RESOURCE", 10);
  opad("LIMIT", 8);
  opad("SCOPE", 9);
  opad("ACTION", 18);
  opad("KILL#", 7);
  oprintf("SHARED\n");
  for(i = 0; i < n; i++){
    v = &snap.policy[i];
    if(only != 0 && !same(v->progname, only))
      continue;
    for(r = 0; r < NRESOURCE; r++){
      if(v->limit[r] == 0 && v->action[r] == 0)
        continue;
      opad(v->progname, 16);
      opad(snap.res_name[r], 10);
      onumw(v->limit[r], 8);
      opad(v->scope[r] == SCOPE_PROGRAM ? "program" : v->scope[r] == SCOPE_GROUP ? "group" : "process", 9);
      opad(action_str(v->action[r], ab), 18);
      if(v->action[r] & ACTION_KILL)
        onumw(v->kill_after_index0[r] + 1, 7);
      else
        opad("-", 7);
      if(v->scope[r] == SCOPE_PROGRAM || v->scope[r] == SCOPE_GROUP)
        oprintf("%d used, %d violation(s)\n", v->shared_used[r], v->shared_violations[r]);
      else
        oprintf("-\n");
    }
  }
}

static void
cmd_ownermem(void)
{
  char *pg;
  int i, ex, n;

  if(take_snapshot()){
    n = clamp(snap.npool, PS_MAXPOOL);
    for(i = 0; i < n; i++)
      if(is(snap.pool_name[i], "owner"))
        oprintf("Owner pool: %d of %d pages in use\n",
                snap.pool_total[i] - snap.pool_free[i], snap.pool_total[i]);
  }
  ex = gate(SVC_EXPOSURE, 0, 0);
  oprintf("Owner pool is mapped in %d of %d page tables (expected 1: the Owner's)\n", ex & 255, ex >> 8);
  pg = (char*)gate(SVC_PAGE_ALLOC, 0, 0);
  if(pg == 0){
    oprintf("Owner pool test: no free page\n");
    return;
  }
  for(i = 0; i < PGSZ; i++)
    pg[i] = (char)(i * 7 + 1);
  for(i = 0; i < PGSZ; i++)
    if(pg[i] != (char)(i * 7 + 1))
      break;
  oprintf("Owner pool test page at %x: write and read back %s\n", (int)pg, i == PGSZ ? "ok" : "FAILED");
  gate(SVC_PAGE_FREE, (uint)pg, 0);
}

// ---- kill and killall ----

static int leave;               // set when a confirmation was cut short (idle or Ctrl-])
static int pids[PS_MAXPROC];    // matches found by killall

static char*
argof(char *line, char *word)    // the text after the command word, without leading spaces
{
  char *s = line + slen(word);

  while(*s == ' ')
    s++;
  return s;
}

static int
parse_pid(char *s)               // a plain decimal number, or -1
{
  int n = 0;

  if(*s < '0' || *s > '9')
    return -1;
  for(; *s >= '0' && *s <= '9'; s++){
    n = n * 10 + (*s - '0');
    if(n > 100000)
      return -1;
  }
  return *s == 0 ? n : -1;
}

static int
same(const char *a, const char *b)   // process names are at most 15 characters
{
  int i;

  for(i = 0; i < 16; i++){
    if(a[i] != b[i])
      return 0;
    if(a[i] == 0)
      return 1;
  }
  return 1;
}

static int
confirm(char *prompt)            // 1 = yes
{
  char ans[8];
  int n;

  oprintf("%s (y/n): ", prompt);
  n = readline(ans, sizeof(ans), 0);
  if(n < 0){
    leave = 1;
    return 0;
  }
  return n > 0 && (ans[0] == 'y' || ans[0] == 'Y');
}

static void
cmd_kill(char *arg)
{
  struct ps_proc *p;
  int pid, i, n, r;

  pid = parse_pid(arg);
  if(pid < 0){
    oprintf("usage: kill <pid>\n");
    return;
  }
  if(pid == 1){
    oprintf("refused: pid 1 (init) cannot be killed; the system would stop\n");
    return;
  }
  if(pid == gate(SVC_GETPID, 0, 0)){
    oprintf("refused: the Owner cannot be killed\n");
    return;
  }
  if(!take_snapshot())
    return;
  n = clamp(snap.nproc, PS_MAXPROC);
  for(i = 0; i < n; i++)
    if(snap.proc[i].pid == pid)
      break;
  if(i == n){
    oprintf("no process with pid %d\n", pid);
    return;
  }
  p = &snap.proc[i];
  if(is(p->state, "zombie")){
    oprintf("pid %d (%s) has already exited\n", pid, p->name);
    return;
  }
  r = gate(SVC_KILL, pid, 0);
  if(r == 0)
    oprintf("kill requested for pid %d (%s)\n", pid, p->name);
  else
    oprintf("could not kill pid %d\n", pid);
}

static void
cmd_killall(char *name)
{
  struct ps_proc *p;
  int i, n, cnt = 0, ok = 0, bad = 0, mypid;

  if(*name == 0){
    oprintf("usage: killall <program>\n");
    return;
  }
  if(!take_snapshot())
    return;
  mypid = gate(SVC_GETPID, 0, 0);
  n = clamp(snap.nproc, PS_MAXPROC);
  for(i = 0; i < n; i++){
    p = &snap.proc[i];
    if(p->pid == 1 || p->pid == mypid || is(p->state, "zombie"))
      continue;
    if(same(p->name, name))
      pids[cnt++] = p->pid;
  }
  if(cnt == 0){
    oprintf("no running process named %s\n", name);
    return;
  }
  oprintf("%d process(es) named %s: pid", cnt, name);
  for(i = 0; i < cnt; i++)
    oprintf(" %d", pids[i]);
  oprintf("\n");
  if(!confirm("Kill them"))
    return;
  for(i = 0; i < cnt; i++){
    if(gate(SVC_KILL, pids[i], 0) == 0)
      ok++;
    else
      bad++;
  }
  oprintf("kill requested for %d process(es), %d failed\n", ok, bad);
}

// ---- rule editing: changes apply at once; the file is written after the session ----

static int save_pending;        // 1 = write /owner/rules once the session has ended

static char*
token(char *s, char *out, int max)     // copies one word into out, returns the rest
{
  int n = 0;

  while(*s == ' ')
    s++;
  while(*s && *s != ' '){
    if(n < max - 1)
      out[n++] = *s;
    s++;
  }
  out[n] = 0;
  return s;
}

static int
parse_uint(char *s, int max)            // a plain decimal number up to max, or -1
{
  int n = 0, d;

  if(*s < '0' || *s > '9')
    return -1;
  for(; *s >= '0' && *s <= '9'; s++){
    d = *s - '0';
    if(n > (max - d) / 10)
      return -1;
    n = n * 10 + d;
  }
  return *s == 0 ? n : -1;
}

static int
parse_action(char *s)                   // count, report, kill, deny joined with +; -1 if unknown
{
  char w[12];
  int mask = 0, n;

  while(*s){
    n = 0;
    while(*s && *s != '+'){
      if(n < 11)
        w[n++] = *s;
      s++;
    }
    w[n] = 0;
    if(*s == '+')
      s++;
    if(same(w, "count"))
      ;
    else if(same(w, "report"))
      mask |= ACTION_REPORT;
    else if(same(w, "kill"))
      mask |= ACTION_KILL;
    else if(same(w, "deny"))
      mask |= ACTION_DENY;
    else
      return -1;
  }
  return mask;
}

// ---- limits per kind of group ----
static char*
kr_act(int a)
{
  if((a & ACTION_REPORT) && (a & ACTION_KILL))
    return "report+kill";
  if(a & ACTION_KILL)
    return "kill";
  if(a & ACTION_REPORT)
    return "report";
  return "-";
}

static void
oplim(int v, int width)             // a limit in percent, or - for none, padded to width
{
  char b[8];
  int n = 0;

  if(v <= 0){
    opad("-", width);
    return;
  }
  if(v >= 100){
    b[n++] = '1';
    b[n++] = '0';
    b[n++] = '0';
  } else {
    if(v >= 10)
      b[n++] = '0' + v / 10;
    b[n++] = '0' + v % 10;
  }
  b[n++] = '%';
  b[n] = 0;
  opad(b, width);
}

static void
opcnt(int v, int width)             // a plain count, or - for none, padded to width
{
  char b[16], t[12];
  int i = 0, n = 0;

  if(v <= 0){
    opad("-", width);
    return;
  }
  while(v > 0){
    t[i++] = '0' + v % 10;
    v /= 10;
  }
  while(i > 0)
    b[n++] = t[--i];
  b[n] = 0;
  opad(b, width);
}

static char*
kr_name(int w)
{
  return w == KR_CPU ? "cpu" : (w == KR_MEM ? "memory" : (w == KR_CPUTIME ? "cputime" : "stdout"));
}

static void
kr_row(int k, int w, int lim, int act)      // one kind rule, in the columns of the program table
{
  opad(kind_name(k), 16);
  opad(kr_name(w), 10);
  if(w < 2)
    oplim(lim, 8);
  else
    opcnt(lim, 8);
  opad("group", 9);
  oprintf("%s\n", kr_act(act));
}

static void
kindrules_show(int only)             // the kind rules of every kind that has one, or of one kind (GK_*); only = -1 means all
{
  int k, w, n = 0;

  if(!take_snapshot())
    return;
  for(k = GK_APP; k <= GK_UTILITY; k++){
    if(only >= 0 && k != only)
      continue;
    for(w = 0; w < 4; w++)
      if(snap.kindrule[k].limit[w] > 0)
        n++;
  }
  if(n == 0){
    if(only >= 0)
      oprintf("no rules for %s\n", kind_name(only));
    return;
  }
  if(only < 0)
    oprintf("\n");
  opad("KIND", 16);
  opad("RESOURCE", 10);
  opad("LIMIT", 8);
  opad("SCOPE", 9);
  oprintf("ACTION\n");
  for(k = GK_APP; k <= GK_UTILITY; k++){
    if(only >= 0 && k != only)
      continue;
    for(w = 0; w < 4; w++)
      if(snap.kindrule[k].limit[w] > 0)
        kr_row(k, w, snap.kindrule[k].limit[w], snap.kindrule[k].action[w]);
  }
}

static void
limit_kind(int kind, char *res, char *num, char *act)
{
  struct kind_req kq;
  int which, n, action = 0;

  if(kind == GK_SYSTEM){
    oprintf("refused: System is never limited; killing it would stop the system or the Owner\n");
    return;
  }
  if(same(res, "cpu"))
    which = KR_CPU;
  else if(same(res, "mem") || same(res, "memory"))
    which = KR_MEM;
  else if(same(res, "cputime"))
    which = KR_CPUTIME;
  else if(same(res, "stdout"))
    which = KR_STDOUT;
  else {
    oprintf("a limit for a kind uses the resource cpu, memory (percent of the whole machine), cputime or stdout (counts for the whole group)\n");
    return;
  }
  n = parse_uint(num, which < 2 ? 100 : 1000000000);
  if(n < 0){
    if(which < 2)
      oprintf("the limit is a percent from 0 to 100; 0 removes it\n");
    else
      oprintf("the limit is a count (ticks or writes) above 0; 0 removes it\n");
    return;
  }
  if(n > 0){
    if(act[0] == 0){
      oprintf("an action is required: report, kill, or report+kill\n");
      return;
    }
    action = parse_action(act);
    if(action <= 0 || (action & ~(ACTION_REPORT | ACTION_KILL)) != 0){
      oprintf("the action for a kind is report, kill, or report+kill\n");
      return;
    }
  }
  kq.kind = kind;
  kq.which = which;
  kq.limit = n;
  kq.action = action;
  if(gate(SVC_KINDRULE_SET, (uint)&kq, sizeof(kq)) < 0){
    oprintf("could not set the rule\n");
    return;
  }
  if(n == 0)
    oprintf("limit removed for %s %s (in effect now; you will be asked to save when you exit)\n", kind_name(kind), res);
  else if(which < 2)
    oprintf("rule set: %s %s limit %d percent (in effect now; you will be asked to save when you exit)\n", kind_name(kind), res, n);
  else
    oprintf("rule set: %s %s limit %d for each group (in effect now; you will be asked to save when you exit)\n", kind_name(kind), res, n);
}

static void
unrule_kind(int kind)
{
  struct kind_req kq;
  int w, bad = 0;

  if(kind == GK_SYSTEM){
    oprintf("System is never limited, so it has no rules\n");
    return;
  }
  for(w = 0; w < 4; w++){
    kq.kind = kind;
    kq.which = w;
    kq.limit = 0;
    kq.action = 0;
    if(gate(SVC_KINDRULE_SET, (uint)&kq, sizeof(kq)) < 0)
      bad = 1;
  }
  if(bad)
    oprintf("could not remove the limits\n");
  else
    oprintf("all limits for %s removed: cpu, memory, cputime, stdout; a manifest may now ask for any amount (in effect now; you will be asked to save when you exit)\n", kind_name(kind));
}

// ---- the program registry ----
static void
ohex(unsigned char *h, int n)
{
  static const char d[] = "0123456789abcdef";
  int i;

  for(i = 0; i < n; i++){
    oputc(d[h[i] >> 4]);
    oputc(d[h[i] & 15]);
  }
}

static char*
reg_word(char *s, char *out, int n)      // copies the next word of s to out; returns the rest of s
{
  int i = 0;

  while(*s == ' ' || *s == '\t')
    s++;
  while(*s && *s != ' ' && *s != '\t' && *s != '\n' && i < n - 1)
    out[i++] = *s++;
  out[i] = 0;
  return s;
}

static void
reg_status_line(void)
{
  oprintf("program registry: %s\n", gate(SVC_REG_MODE, 0, 0) == REG_ENFORCE ? "on" : "off");
}

// ---- registry install: the staged bundle and its manifest ----
// The kernel reads /inbox/<app>/ and hashes it; the text of the manifest is checked here.
static struct inst_view iv;           // the staged bundle, filled in by the kernel (about 1.2 KB)
#define REQ_MAX_CPUTIME 10000    // the most CPU ticks per process that this system grants an app
#define REQ_MAX_STDOUT  100000   // the most console writes per process that this system grants an app

static struct {                       // what the manifest says
  int  kindv;                      // GK_APP or GK_AGENT
  int  reqcpu, reqout;             // the cputime and stdout it requires; 0 = not asked
  char kind[8];
  char goal[80];
  unsigned char cmdhash[32];
  char needs[8][16];
  int  nneeds;
  char limit[4][40];
  int  nlimit;
  char report[24];
} mfst;

static int
mf_len(char *s)
{
  int n = 0;

  while(s[n])
    n++;
  return n;
}

static int
mf_prefix(char *s, char *p)           // 1 if s starts with p
{
  while(*p){
    if(*s != *p)
      return 0;
    s++;
    p++;
  }
  return 1;
}

static char*
mf_skip(char *s)                      // skips spaces and tabs
{
  while(*s == ' ' || *s == '\t')
    s++;
  return s;
}

static char*
mf_word(char *s, char *out, int max)  // the next word, ended by a space, tab, comma or semicolon; returns the rest
{
  int n = 0;

  s = mf_skip(s);
  while(*s && *s != ' ' && *s != '\t' && *s != ',' && *s != ';' && n < max - 1)
    out[n++] = *s++;
  out[n] = 0;
  return s;
}

static int
mf_hexval(char c)
{
  if(c >= '0' && c <= '9')
    return c - '0';
  if(c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if(c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

static int
mf_hex(char *s, unsigned char *out)   // 64 hexadecimal digits into 32 bytes: 0, or -1
{
  int i, hi, lo;

  for(i = 0; i < 32; i++){
    hi = mf_hexval(s[2 * i]);
    if(hi < 0)
      return -1;
    lo = mf_hexval(s[2 * i + 1]);
    if(lo < 0)
      return -1;
    out[i] = hi * 16 + lo;
  }
  return 0;
}

static int mf_quiet;                   // 1 while the manifest is checked only to find the wrong line: nothing is printed
static int mf_badline, lnname, lndeps, lncmd, lnreqc, lnreqo;   // the line to mark, and the lines of the keys that are checked later
#define MFP(...) do { if(!mf_quiet) oprintf(__VA_ARGS__); } while(0)

static int
mf_err(int ln, char *msg)
{
  mf_badline = ln;
  MFP("manifest line %d: %s\n", ln, msg);
  return -1;
}

static int
mf_registered(char *name)             // 1 if name is a preinstalled program (installed apps come with part 2)
{
  struct reg_view rv;
  int i, total;

  rv.index = 0;
  gate(SVC_REG_ENTRY, (uint)&rv, sizeof(rv));
  total = rv.total;
  for(i = 0; i < total; i++){
    rv.index = i;
    if(gate(SVC_REG_ENTRY, (uint)&rv, sizeof(rv)) < 0)
      break;
    if(same(rv.name, name))
      return 1;
  }
  return 0;
}

// Parses iv.manifest and checks it. 0 if it is acceptable; otherwise -1 after printing the reason.
static int
inst_manifest(char *app)
{
  char *s = iv.manifest, *e, *r;
  char line[104], w[32], hx[72], res[16], num[16];
  int ln = 0, n, i, k, a, lim;
  int have_name = 0, have_kind = 0, have_goal = 0, have_cmd = 0, have_needs = 0, have_rep = 0;

  mfst.nneeds = 0;
  mfst.nlimit = 0;
  mfst.reqcpu = mfst.reqout = 0;
  lnname = lndeps = lncmd = lnreqc = lnreqo = mf_badline = 0;
  mfst.kind[0] = 0;
  mfst.goal[0] = 0;
  mfst.report[0] = 0;
  while(*s){
    e = s;
    while(*e && *e != '\n')
      e++;
    n = e - s;
    ln++;
    mf_badline = ln;
    if(n > 100)
      return mf_err(ln, "the line is longer than 100 characters");
    for(i = 0; i < n; i++)
      line[i] = s[i];
    line[n] = 0;
    if(n > 0 && line[n - 1] == '\r')
      line[n - 1] = 0;
    s = *e ? e + 1 : e;
    r = mf_skip(line);
    if(*r == 0 || *r == '#')
      continue;

    if(mf_prefix(r, "name:")){
      if(have_name)
        return mf_err(ln, "name is given twice");
      r = mf_word(r + 5, w, sizeof(w));
      if(w[0] == 0 || *mf_skip(r))
        return mf_err(ln, "name: one word is expected");
      if(!same(w, app)){
        MFP("manifest line %d: the name %s must equal the bundle directory %s\n", ln, w, app);
        return -1;
      }
      have_name = 1;
      lnname = ln;
    } else if(mf_prefix(r, "kind:")){
      if(have_kind)
        return mf_err(ln, "kind is given twice");
      r = mf_word(r + 5, w, sizeof(w));
      if(w[0] == 0 || *mf_skip(r))
        return mf_err(ln, "kind: one word is expected");
      k = parse_kind(w);
      if(k != GK_APP && k != GK_AGENT){
        MFP("manifest line %d: kind %s cannot be installed: use app or agent\n", ln, w);
        return -1;
      }
      for(i = 0; kind_name(k)[i] && i < 7; i++)
        mfst.kind[i] = kind_name(k)[i];
      mfst.kind[i] = 0;
      mfst.kindv = k;
      have_kind = 1;
    } else if(mf_prefix(r, "goal:")){
      if(have_goal)
        return mf_err(ln, "goal is given twice");
      r = mf_skip(r + 5);
      n = mf_len(r);
      if(n == 0)
        return mf_err(ln, "goal is empty");
      if(n > 79)
        return mf_err(ln, "the goal is longer than 79 characters");
      for(i = 0; i <= n; i++)
        mfst.goal[i] = r[i];
      have_goal = 1;
    } else if(mf_prefix(r, "commands:")){
      if(have_cmd)
        return mf_err(ln, "commands is given twice");
      r = mf_word(r + 9, w, sizeof(w));
      if(w[0] == 0)
        return mf_err(ln, "commands: a name and the sha-256 of its program are expected");
      if(!same(w, app)){
        MFP("manifest line %d: command %s: phase 1 allows exactly one command, named like the app (%s)\n", ln, w, app);
        return -1;
      }
      r = mf_word(r, hx, sizeof(hx));
      if(mf_len(hx) != 64 || mf_hex(hx, mfst.cmdhash) < 0)
        return mf_err(ln, "commands: the sha-256 must be 64 hexadecimal digits");
      if(*mf_skip(r))
        return mf_err(ln, "phase 1 allows exactly one command, named like the app");
      have_cmd = 1;
      lncmd = ln;
    } else if(mf_prefix(r, "deps:")){
      if(have_needs)
        return mf_err(ln, "deps is given twice");
      have_needs = 1;
      lndeps = ln;
      r = r + 5;
      for(;;){
        r = mf_word(r, w, sizeof(w));
        if(w[0] == 0)
          break;
        if(mfst.nneeds >= 8)
          return mf_err(ln, "deps: at most 8 programs");
        if(mf_len(w) > 14)
          return mf_err(ln, "deps: a program name is longer than 14 characters");
        for(i = 0; i <= mf_len(w); i++)
          mfst.needs[mfst.nneeds][i] = w[i];
        mfst.nneeds++;
        r = mf_skip(r);
        if(*r == ',')
          r++;
      }
      if(*mf_skip(r))
        return mf_err(ln, "deps: a program name was expected");
    } else if(mf_prefix(r, "requires:")){
      r = mf_skip(r + 9);
      n = mf_len(r);
      if(mfst.nlimit >= 2)
        return mf_err(ln, "at most 2 requires lines");
      if(n > 39)
        return mf_err(ln, "the requires line is longer than 39 characters");
      for(i = 0; i <= n; i++)
        mfst.limit[mfst.nlimit][i] = r[i];
      r = mf_word(r, res, sizeof(res));
      r = mf_word(r, num, sizeof(num));
      if(!same(res, "stdout") && !same(res, "cputime"))
        return mf_err(ln, "requires: the resource is stdout or cputime");
      a = parse_uint(num, 1000000000);
      if(a <= 0)
        return mf_err(ln, "requires: the amount must be a number above 0");
      if(same(res, "cputime")){
        if(mfst.reqcpu)
          return mf_err(ln, "requires: cputime is already given");
        mfst.reqcpu = a;
        lnreqc = ln;
      } else {
        if(mfst.reqout)
          return mf_err(ln, "requires: stdout is already given");
        mfst.reqout = a;
        lnreqo = ln;
      }
      if(*mf_skip(r))
        return mf_err(ln, "requires: write it as: requires: <resource> <amount>");
      mfst.nlimit++;
    } else if(mf_prefix(r, "report:")){
      if(have_rep)
        return mf_err(ln, "report is given twice");
      r = mf_skip(r + 7);
      n = mf_len(r);
      if(n > 23)
        return mf_err(ln, "report: the line is too long");
      for(i = 0; i <= n; i++)
        mfst.report[i] = r[i];
      r = mf_word(r, w, sizeof(w));
      if(!same(w, "every"))
        return mf_err(ln, "report: write it as: report: every <n> ticks");
      r = mf_word(r, w, sizeof(w));
      if(parse_uint(w, 1000000000) <= 0)
        return mf_err(ln, "report: a number above 0 is expected after every");
      r = mf_word(r, w, sizeof(w));
      if(w[0] && !same(w, "ticks"))
        return mf_err(ln, "report: write it as: report: every <n> ticks");
      if(*mf_skip(r))
        return mf_err(ln, "report: nothing may follow ticks");
      have_rep = 1;
    } else {
      mf_word(r, w, sizeof(w));
      MFP("manifest line %d: unknown key \"%s\"\n", ln, w);
      return -1;
    }
  }
  mf_badline = 0;                   // the errors below name no line of their own, unless they set one
  if(!have_name){
    MFP("manifest: name is missing\n");
    return -1;
  }
  if(!have_kind){
    MFP("manifest: kind is missing\n");
    return -1;
  }
  if(!have_goal){
    MFP("manifest: goal is missing\n");
    return -1;
  }
  if(!have_cmd){
    MFP("manifest: commands is missing\n");
    return -1;
  }
  if(mf_registered(app)){
    mf_badline = lnname;
    MFP("manifest line %d: the name %s is already used by a registered program\n", lnname, app);
    return -1;
  }
  for(i = 0; i < mfst.nneeds; i++)
    if(!mf_registered(mfst.needs[i])){
      mf_badline = lndeps;
      MFP("manifest line %d: missing dependency: %s\n", lndeps, mfst.needs[i]);
      return -1;
    }
  if(mfst.reqcpu || mfst.reqout){          // the system's own rules say how much an app of this kind may ask for
    if(!take_snapshot()){
      MFP("could not read the rules\n");
      return -1;
    }
    lim = snap.kindrule[mfst.kindv].limit[KR_CPUTIME];
    if(lim > 0 && mfst.reqcpu > lim){
      mf_badline = lnreqc;
      MFP("manifest line %d: requires cputime %d is more than the %s rule allows (%d)\n", lnreqc, mfst.reqcpu, mfst.kind, lim);
      return -1;
    }
    lim = snap.kindrule[mfst.kindv].limit[KR_STDOUT];
    if(lim > 0 && mfst.reqout > lim){
      mf_badline = lnreqo;
      MFP("manifest line %d: requires stdout %d is more than the %s rule allows (%d)\n", lnreqo, mfst.reqout, mfst.kind, lim);
      return -1;
    }
  }
  for(i = 0; i < 32; i++)
    if(mfst.cmdhash[i] != iv.phash[i]){
      mf_badline = lncmd;
      MFP("manifest line %d: the program %s does not match the hash in its manifest\n", lncmd, app);
      return -1;
    }
  return 0;
}

// The manifest as the kernel read it, numbered like the parser counts its lines. It comes from a bundle that
// anyone can write, so only plain characters are printed and a long line is cut.
static void
show_manifest(int bad)              // bad = the number of the line to mark with >>, or 0
{
  char *s = iv.manifest;
  int ln = 1, col = 0;

  oprintf("manifest.txt (%d bytes):\n", iv.mlen);
  oprintf("%s%d | ", ln == bad ? ">> " : "   ", ln);
  for(; *s; s++){
    if(*s == '\n'){
      oputc('\n');
      col = 0;
      if(s[1]){
        ln++;
        oprintf("%s%d | ", ln == bad ? ">> " : "   ", ln);
      }
      continue;
    }
    if(col >= 100){
      if(col == 100)
        oprintf("...");
      col++;
      continue;
    }
    oputc(*s >= 32 && *s < 127 ? *s : '?');
    col++;
  }
  if(iv.mlen > 0 && iv.manifest[iv.mlen - 1] != '\n')
    oputc('\n');
}

static struct inst_req inst_q;      // the approved install, sent to the kernel once the session has closed
static int install_pending;         // 1 = the Owner approved an install

static void
install_commit(void)
{
  char *a = inst_q.app;

  if(gate(SVC_INST_COMMIT, (uint)&inst_q, sizeof(inst_q)) < 0){
    oprintf("[Owner] %s was not installed: the request was refused\n", a);
    return;
  }
  switch(inst_q.status){
  case INST_C_OK:
    oprintf("[Owner] %s installed in /apps/%s/. Type %s to run it; the registry lists it too\n", a, a, a);
    break;
  case INST_C_NOFS:
    oprintf("[Owner] %s was not installed: the file system is not ready\n", a);
    break;
  case INST_C_EXISTS:
    oprintf("[Owner] %s was not installed: it is already installed, or /apps/%s is in the way\n", a, a);
    break;
  case INST_C_FULL:
    oprintf("[Owner] %s was not installed: the Owner keeps at most 8 installed apps\n", a);
    break;
  case INST_C_COPY:
    oprintf("[Owner] %s was not installed: the bundle could not be copied to /apps/%s/ (is the disk full?); nothing was kept\n", a, a);
    break;
  case INST_C_CHANGED:
    oprintf("[Owner] %s was not installed: the bundle in /inbox/%s/ changed after you approved it; nothing was kept\n", a, a);
    break;
  case INST_C_RECORD:
    oprintf("[Owner] %s was not installed: /owner/apps could not be written; nothing was kept\n", a);
    break;
  case INST_C_RULES:
    oprintf("[Owner] %s was not installed: the rule table has no room for its requirements; nothing was kept\n", a);
    break;
  default:
    oprintf("[Owner] %s was not installed: a bad request\n", a);
  }
}

// The entries of the staged bundle, as the kernel saw them, with the ones that do not belong marked.
static void
show_bundle(char *app)
{
  int i, shown = iv.nent < 8 ? iv.nent : 8;

  oprintf("bundle /inbox/%s/ contains:\n", app);
  for(i = 0; i < shown; i++){
    if(same(iv.ent[i], "manifest.txt") || same(iv.ent[i], app))
      oprintf("   %s\n", iv.ent[i]);
    else
      oprintf(">> %s       <- not allowed\n", iv.ent[i]);
  }
  if(iv.nent > shown)
    oprintf("   ... and %d more\n", iv.nent - shown);
  if(iv.nent == 0)
    oprintf("   (nothing)\n");
}

static struct uninst_req uninst_q;  // the approved uninstall, sent to the kernel once the session has closed
static int uninstall_pending;       // 1 = the Owner approved an uninstall

static void
uninstall_commit(void)
{
  char *a = uninst_q.app;

  if(gate(SVC_UNINST, (uint)&uninst_q, sizeof(uninst_q)) < 0){
    oprintf("[Owner] %s was not uninstalled: the request was refused\n", a);
    return;
  }
  switch(uninst_q.status){
  case UNINST_OK:
    oprintf("[Owner] %s uninstalled: its processes ended, and its rules and /apps/%s/ are removed\n", a, a);
    break;
  case UNINST_NOFS:
    oprintf("[Owner] %s was not uninstalled: the file system is not ready\n", a);
    break;
  case UNINST_NOAPP:
    oprintf("[Owner] %s was not uninstalled: it is not an installed app\n", a);
    break;
  case UNINST_RECORD:
    oprintf("[Owner] %s was not uninstalled: /owner/apps could not be written; nothing was changed\n", a);
    break;
  case UNINST_FILES:
    oprintf("[Owner] %s uninstalled, but /apps/%s/ could not be removed now; it is removed at the next boot\n", a, a);
    break;
  default:
    oprintf("[Owner] %s was not uninstalled: a bad request\n", a);
  }
}

static void
cmd_uninstall(char *app)
{
  static char prompt[40];
  static const char pre[] = "Uninstall ";
  struct reg_view rv;
  int i, n, total, npre, found = 0;

  if(install_pending || uninstall_pending){   // one install or removal per session: the earlier approval stays
    oprintf("%s is already approved to be %s in this session: leave the session first, then try again\n",
            install_pending ? inst_q.app : uninst_q.app, install_pending ? "installed" : "removed");
    return;
  }
  for(n = 0; app[n]; n++)
    if(app[n] == '/')
      break;
  if(n == 0 || n > 14 || app[n]){
    oprintf("an app name is 1 to 14 characters, with no /\n");
    return;
  }
  rv.index = 0;
  gate(SVC_REG_ENTRY, (uint)&rv, sizeof(rv));
  total = rv.total;
  npre = rv.npre;
  for(i = 0; i < total; i++){
    rv.index = i;
    if(gate(SVC_REG_ENTRY, (uint)&rv, sizeof(rv)) < 0)
      break;
    if(same(rv.name, app)){
      found = i >= npre ? 2 : 1;
      break;
    }
  }
  if(found == 1){
    oprintf("%s is a preinstalled program: it cannot be uninstalled\n", app);
    return;
  }
  if(found == 0){
    oprintf("no installed app named %s\n", app);
    return;
  }
  oprintf("Uninstalling %s ends its processes and removes /apps/%s/ and its rules.\n", app, app);
  for(i = 0; i < 10; i++)
    prompt[i] = pre[i];
  for(i = 0; i < 14 && app[i]; i++)
    prompt[10 + i] = app[i];
  prompt[10 + i] = 0;
  if(!confirm(prompt)){
    oprintf("uninstall cancelled\n");
    return;
  }
  for(i = 0; i < 16; i++)
    uninst_q.app[i] = 0;
  for(i = 0; i < 15 && app[i]; i++)
    uninst_q.app[i] = app[i];
  uninst_q.status = 0;
  uninstall_pending = 1;
  oprintf("approved. %s is removed when you leave this session.\n", app);
}

static void
cmd_install(char *app)
{
  static char prompt[40];
  static const char pre[] = "Install ";
  int i, r;

  if(install_pending || uninstall_pending){   // one install or removal per session: the earlier approval stays
    oprintf("%s is already approved to be %s in this session: leave the session first, then try again\n",
            install_pending ? inst_q.app : uninst_q.app, install_pending ? "installed" : "removed");
    return;
  }
  for(i = 0; i < 16; i++)
    iv.app[i] = 0;
  for(i = 0; i < 15 && app[i]; i++)
    iv.app[i] = app[i];
  if(gate(SVC_INST_READ, (uint)&iv, sizeof(iv)) < 0){
    oprintf("could not read the bundle\n");
    return;
  }
  if(iv.mlen > 0 && iv.status != INST_OK)
    show_manifest(0);                // the bundle has another problem: the manifest first, then what is wrong
  switch(iv.status){
  case INST_OK:
    break;
  case INST_BADNAME:
    oprintf("an app name is 1 to 14 characters, with no /\n");
    return;
  case INST_NOBUNDLE:
    oprintf("no bundle /inbox/%s/\n", app);
    return;
  case INST_NOMANIFEST:
    show_bundle(app);
    oprintf("/inbox/%s/ has no manifest.txt\n", app);
    return;
  case INST_NOPROGRAM:
    show_bundle(app);
    oprintf("/inbox/%s/ has no program named %s\n", app, app);
    return;
  case INST_EXTRA:
    show_bundle(app);
    oprintf("unexpected entry: %s (phase 1 allows only manifest.txt and the program named %s)\n", iv.extra, app);
    return;
  case INST_TOOBIG:
    oprintf("the manifest is over 1024 bytes, or the program is too large\n");
    return;
  case INST_BUSY:
    oprintf("the console has held output: try again after it ends\n");
    return;
  default:
    oprintf("could not read the bundle\n");
    return;
  }
  mf_quiet = 1;                      // first find out whether the manifest is acceptable, and which line is wrong
  r = inst_manifest(app);
  mf_quiet = 0;
  if(iv.mlen > 0)
    show_manifest(r < 0 ? mf_badline : 0);   // then show it, with the wrong line marked
  if(r < 0){
    inst_manifest(app);              // and say what is wrong with it
    return;
  }
  oprintf("manifest sha-256: ");
  ohex(iv.mhash, 16);
  ohex(iv.mhash + 16, 16);
  oputc('\n');
  oflush();
  for(i = 0; i < 8; i++)
    prompt[i] = pre[i];
  for(i = 0; i < 15 && app[i]; i++)
    prompt[8 + i] = app[i];
  prompt[8 + i] = 0;
  if(!confirm(prompt)){
    oprintf("install cancelled\n");
    return;
  }
  for(i = 0; i < 16; i++)
    inst_q.app[i] = iv.app[i];
  inst_q.status = 0;
  inst_q.kind = mfst.kindv;
  inst_q.reqcpu = mfst.reqcpu;
  inst_q.reqout = mfst.reqout;
  for(i = 0; i < 80; i++)
    inst_q.goal[i] = mfst.goal[i];
  inst_q.goal[79] = 0;
  for(i = 0; i < 24; i++)
    inst_q.report[i] = mfst.report[i];
  inst_q.report[23] = 0;
  for(i = 0; i < 32; i++){
    inst_q.mhash[i] = iv.mhash[i];
    inst_q.phash[i] = iv.phash[i];
  }
  install_pending = 1;
  oprintf("approved. %s is copied to /apps/%s/ and recorded when you leave this session.\n", app, app);
}

// The registry list: by kind (System, Utilities, App, Agent), each in name order. An installed app has * after its name.
static struct reg_view reg_ents[48];

static int
reg_rank(int k)
{
  if(k == GK_SYSTEM)
    return 0;
  if(k == GK_UTILITY)
    return 1;
  if(k == GK_APP)
    return 2;
  return 3;
}

static int
reg_before(struct reg_view *a, struct reg_view *b)       // 1 if a is listed before b
{
  int i, ra = reg_rank(a->kind), rb = reg_rank(b->kind);

  if(ra != rb)
    return ra < rb;
  for(i = 0; i < 16; i++){
    if(a->name[i] != b->name[i])
      return (unsigned char)a->name[i] < (unsigned char)b->name[i];
    if(a->name[i] == 0)
      break;
  }
  return 0;
}

static void
reg_list(int total, int npre)
{
  int order[48], n = 0, i, j, t, w;
  char nb[20];

  for(i = 0; i < total && n < 48; i++){
    reg_ents[n].index = i;
    if(gate(SVC_REG_ENTRY, (uint)&reg_ents[n], sizeof(reg_ents[n])) < 0)
      break;
    n++;
  }
  for(i = 0; i < n; i++){                    // insertion sort of the positions
    for(j = i - 1; j >= 0 && reg_before(&reg_ents[i], &reg_ents[order[j]]); j--)
      order[j + 1] = order[j];
    order[j + 1] = i;
  }
  opad("NAME", 18);
  opad("KIND", 11);
  oprintf("SHA-256 (first 16 digits)\n");
  for(i = 0; i < n; i++){
    w = order[i];
    for(t = 0; t < 15 && reg_ents[w].name[t]; t++)
      nb[t] = reg_ents[w].name[t];
    if(reg_ents[w].index >= npre){
      nb[t++] = ' ';
      nb[t++] = '*';
    }
    nb[t] = 0;
    opad(nb, 18);
    opad(kind_name(reg_ents[w].kind), 11);
    ohex(reg_ents[w].hash, 8);
    oputc('\n');
  }
  if(total > npre)
    oprintf("* installed from /inbox\n");
}

// ---- reports: what an installed app reported, record by record ----
static struct rep_view rpv;         // the kernel's answer, with one record: about 310 bytes

static void
rep_num(unsigned int v, int width)  // a number, padded on the right to width
{
  char b[16], t[12];
  int i = 0, n = 0;

  if(v == 0)
    t[i++] = '0';
  while(v > 0 && i < 11){
    t[i++] = '0' + v % 10;
    v /= 10;
  }
  while(i > 0)
    b[n++] = t[--i];
  b[n] = 0;
  opad(b, width);
}

static unsigned int
rep_dig(char *h, int at, int digits)   // a number written in decimal digits in a record's header
{
  unsigned int v = 0;
  int i;

  for(i = 0; i < digits; i++)
    v = v * 10 + (h[at + i] >= '0' && h[at + i] <= '9' ? h[at + i] - '0' : 0);
  return v;
}

static int
rep_ok(void)                        // 1 if the record starts with the kernel's header
{
  static const char magic[] = "SAFEOS REPORT ";
  int i;

  for(i = 0; i < 14; i++)
    if(rpv.rec[i] != magic[i])
      return 0;
  return 1;
}

static void
rep_text(void)                      // the app's text in the record: trailing spaces cut, only plain characters printed, the rest shown as ?
{
  int i, end = REP_RECSIZE - 1;
  char c;

  while(end > 64 && rpv.rec[end - 1] == ' ')
    end--;
  for(i = 64; i < end; i++){
    c = rpv.rec[i];
    oputc(c >= 32 && c < 127 ? c : '?');
  }
}

static int
rep_fetch(int index, char *app, int recno)   // the status; a message has been printed for REP_BUSY and REP_READ
{
  int i;

  rpv.index = index;
  rpv.recno = recno;
  for(i = 0; i < 16; i++)
    rpv.app[i] = 0;
  for(i = 0; i < 15 && app && app[i]; i++)
    rpv.app[i] = app[i];
  if(gate(SVC_REPORT_READ, (uint)&rpv, sizeof(rpv)) < 0){
    oprintf("could not read the reports\n");
    return REP_BUSY;
  }
  if(rpv.status == REP_BUSY){
    oprintf("the console has held output: try again after it ends\n");
    return REP_BUSY;
  }
  if(rpv.status == REP_READ){
    oprintf("a report record could not be read\n");
    return REP_READ;
  }
  return rpv.status;
}

static void
cmd_reports(char *line)             // "reports": the latest report of every app; "reports <app>": all the reports of one app
{
  char w[2][16];
  char *s;
  int i, k, j, st, total, nrec, late = 0, t;

  s = reg_word(line, w[0], 16);
  reg_word(s, w[1], 16);
  k = same(w[0], "reports") ? 1 : 0;        // skip the command word if it is part of the line
  if(w[k][0] == 0){
    st = rep_fetch(0, 0, -1);
    if(st == REP_BUSY || st == REP_READ)
      return;
    total = rpv.total;
    if(total == 0){
      oprintf("no installed app has a report log\n");
      return;
    }
    opad("APP", 16);
    opad("REPORTS", 9);
    oprintf("LATEST REPORT\n");
    for(i = 0; i < total; i++){
      st = rep_fetch(i, 0, -2);
      if(st == REP_BUSY || st == REP_READ)
        return;
      if(st == REP_NOAPP)
        break;
      opad(rpv.name, 16);
      rep_num(rpv.nrec, 9);
      if(rpv.nrec == 0)
        oprintf("none yet\n");
      else if(!rep_ok())
        oprintf("damaged record\n");
      else {
        t = (int)rep_dig(rpv.rec, 34, 10);
        if((unsigned int)t > rpv.now)
          late = 1;
        oprintf("tick %d%s pid %d: ", t, (unsigned int)t > rpv.now ? "*" : "", (int)rep_dig(rpv.rec, 49, 5));
        rep_text();
        oputc('\n');
      }
    }
    if(late)
      oprintf("* written before the last restart, so its tick cannot be compared with now (tick %d)\n", (int)rpv.now);
    oflush();
    return;
  }
  st = rep_fetch(-1, w[k], -1);
  if(st == REP_BUSY || st == REP_READ)
    return;
  if(st == REP_NOAPP){
    oprintf("no installed app named %s\n", w[k]);
    return;
  }
  nrec = rpv.nrec;
  oprintf("%s report: %d of %d records (now tick %d)\n", rpv.name, nrec, REP_MAXREC, (int)rpv.now);
  if(nrec == 0){
    oprintf("  nothing reported yet\n");
    return;
  }
  for(j = 0; j < nrec; j++){
    st = rep_fetch(-1, w[k], j);
    if(st == REP_BUSY || st == REP_READ)
      return;
    if(st == REP_NOAPP)
      break;
    if(!rep_ok()){
      oprintf("  %d  damaged record\n", j + 1);
      continue;
    }
    t = (int)rep_dig(rpv.rec, 34, 10);
    if((unsigned int)t > rpv.now)
      late = 1;
    oprintf("  %d  tick %d%s  pid %d  ", (int)rep_dig(rpv.rec, 57, 6), t, (unsigned int)t > rpv.now ? "*" : "",
            (int)rep_dig(rpv.rec, 49, 5));
    rep_text();
    oputc('\n');
  }
  oprintf("the number, tick and pid are written by the kernel; the text is written by the app and is not verified\n");
  if(late)
    oprintf("* written before the last restart, so its tick cannot be compared with now\n");
}

static void
cmd_registry(char *line)            // "registry", "registry on", "registry off" or "registry install <app>"
{
  struct reg_view rv;
  char w[3][16];
  char *s;
  int k, m, total;

  s = reg_word(line, w[0], 16);
  s = reg_word(s, w[1], 16);
  reg_word(s, w[2], 16);
  k = same(w[0], "registry") ? 1 : 0;        // skip the command word if it is part of the line
  if(w[k][0] == 0){
    m = gate(SVC_REG_MODE, 0, 0);
    rv.index = 0;
    gate(SVC_REG_ENTRY, (uint)&rv, sizeof(rv));
    total = rv.total;
    oprintf("program registry: %s\n", m == REG_ENFORCE ? "on" : "off");
    oprintf("%d registered programs, %d of them installed apps. On: a program that is not listed does not start.\n", total, total - rv.npre);
    oprintf("Off: it runs as an Agent and is reported once. A change applies at once, and you are asked to save it when you exit.\n");
    reg_list(total, rv.npre);
    oflush();
    return;
  }
  if(k == 0 && same(w[k], "uninstall")){
    if(w[k + 1][0] == 0)
      oprintf("usage: uninstall <app>\n");
    else
      cmd_uninstall(w[k + 1]);
    return;
  }
  if(k == 0 && same(w[k], "install")){
    if(w[k + 1][0] == 0)
      oprintf("usage: install <app>   (the bundle is staged in /inbox/<app>/)\n");
    else
      cmd_install(w[k + 1]);
    return;
  }
  if(same(w[k], "on"))
    m = REG_ENFORCE;
  else if(same(w[k], "off"))
    m = REG_REPORT;
  else {
    oprintf("usage: registry   or   registry on   or   registry off   (installing has its own commands: install <app>, uninstall <app>)\n");
    return;
  }
  if(gate(SVC_REG_MODE, 1, m) < 0){
    oprintf("could not change the registry\n");
    return;
  }
  oprintf("program registry: %s (in effect now; you will be asked to save when you exit)\n", m == REG_ENFORCE ? "on" : "off");
}

static void
cmd_limit(char *arg)
{
  char prog[24], res[24], num[24], act[24], scp[24];
  struct rule_req rq;
  char *s = arg;
  int which, n, action = 0, scope = SCOPE_PROCESS, r, i;
  int k, n0;

  s = token(s, prog, sizeof(prog));
  s = token(s, res, sizeof(res));
  s = token(s, num, sizeof(num));
  s = token(s, act, sizeof(act));
  s = token(s, scp, sizeof(scp));
  if(prog[0] == 0 || res[0] == 0 || num[0] == 0){
    oprintf("usage: limit <program> <resource> <n> <action> process|program|group\n");
    oprintf("       action: count, report, kill, deny, joined with + (for example kill+deny)\n");
    oprintf("       limit <kind> <resource> <n> <action> group   (kinds: App, Agent, Utilities; resources: cpu, memory; actions: report, kill)\n");
    oprintf("       n = 0 removes that limit\n");
    oprintf("  registry   show the program registry; registry mode report|enforce changes the mode\n");
    return;
  }
  if(slen(prog) > 15){
    oprintf("program name too long (at most 15 characters)\n");
    return;
  }
  if(same(prog, "init") || same(prog, "initcode") || same(prog, "owner")){
    oprintf("refused: no rules for %s; killing it would stop the system or the Owner\n", prog);
    return;
  }
  k = parse_kind(prog);
  n0 = parse_uint(num, 1000000000);
  if(n0 > 0 && scp[0] == 0){
    oprintf("end the rule with process or program (a program rule) or group (a kind rule)\n");
    return;
  }
  if(scp[0] != 0 && !same(scp, "process") && !same(scp, "program") && !same(scp, "group")){
    oprintf("the last word must be process, program or group\n");
    return;
  }
  if(k >= 0 && scp[0] != 0 && !same(scp, "group")){
    oprintf("%s is a kind; end a kind rule with group\n", prog);
    return;
  }
  if(k >= 0){                           // a limit for a whole kind of group
    limit_kind(k, res, num, act);
    return;
  }
  if(!take_snapshot())
    return;
  for(which = 0; which < NRESOURCE; which++)
    if(same(res, snap.res_name[which]))
      break;
  if(which == NRESOURCE){
    oprintf("unknown resource %s; resources:", res);
    for(which = 0; which < NRESOURCE; which++)
      oprintf(" %s", snap.res_name[which]);
    oprintf("\n");
    return;
  }
  n = parse_uint(num, 1000000000);
  if(n < 0){
    oprintf("the limit must be a number from 0 to 1000000000\n");
    return;
  }
  if(n > 0){
    if(act[0] == 0){
      oprintf("an action is required: count, report, kill, deny\n");
      return;
    }
    action = parse_action(act);
    if(action < 0){
      oprintf("unknown action %s\n", act);
      return;
    }
    if(scp[0] != 0){
      if(same(scp, "process"))
        scope = SCOPE_PROCESS;
      else if(same(scp, "program"))
        scope = SCOPE_PROGRAM;
      else if(same(scp, "group"))
        scope = SCOPE_GROUP;
      else {
        oprintf("scope must be process or program\n");
        return;
      }
    }
  }
  for(i = 0; i < 16; i++)
    rq.prog[i] = 0;
  copy(rq.prog, prog);
  rq.which = which;
  rq.limit = n;
  rq.action = action;
  rq.scope = scope;
  r = gate(SVC_RULE_SET, (uint)&rq, sizeof(rq));
  if(r == -2){
    oprintf("the rule table is full (%d programs); use unrule to free a row\n", RULE_MAX);
    return;
  }
  if(r < 0){
    oprintf("could not set the rule\n");
    return;
  }
  if(n == 0)
    oprintf("limit removed for %s %s (in effect now; you will be asked to save when you exit)\n", prog, res);
  else
    oprintf("rule set: %s %s limit %d (in effect now; you will be asked to save when you exit)\n", prog, res, n);
}

static void rules_show(char *only);
static void kindrules_show(int only);

static void
cmd_rules_cmd(char *arg)             // rules   or   rules <program>   or   rules <kind>
{
  char w[24], extra[16];
  char *rest;
  int k;

  rest = token(arg, w, sizeof(w));
  token(rest, extra, sizeof(extra));
  if(extra[0]){
    oprintf("usage: rules   or   rules <program>   or   rules <kind>\n");
    return;
  }
  if(w[0] == 0){
    rules_show(0);
    kindrules_show(-1);
  } else {
    k = parse_kind(w);
    if(k == GK_SYSTEM){
      oprintf("System is never limited, so it has no rules\n");
      return;
    }
    if(k >= 0)
      kindrules_show(k);
    else if(slen(w) > 15)
      oprintf("no rules for %s\n", w);
    else
      rules_show(w);
  }
  if(gate(SVC_RULES_STATE, 0, 0) > 0)
    oprintf("unsaved changes (in effect now, lost at reboot): exit to save, or revert\n");
}

static void
cmd_unrule(char *arg)               // unrule <program> [resource]   or   unrule <kind> [resource]
{
  char prog[24], res[16], extra[16];
  char *rest;
  struct rule_req rq;
  int k, w, i, r;

  rest = token(arg, prog, sizeof(prog));
  rest = token(rest, res, sizeof(res));
  token(rest, extra, sizeof(extra));
  if(prog[0] == 0){
    oprintf("usage: unrule <program> [resource]   or   unrule <kind> [resource]   (resources: stdout cputime; for a kind also cpu memory)\n");
    return;
  }
  if(extra[0]){
    oprintf("unrule: too many words; nothing was removed\n");
    return;
  }
  k = parse_kind(prog);
  if(k >= 0){
    if(res[0])
      limit_kind(k, res, "0", "");     // one limit of the kind
    else
      unrule_kind(k);                  // all of them
    return;
  }
  if(slen(prog) > 15){
    oprintf("no rules for %s\n", prog);
    return;
  }
  if(res[0] == 0){
    if(gate(SVC_RULE_REMOVE, (uint)prog, slen(prog)) < 0)
      oprintf("no rules for %s\n", prog);
    else
      oprintf("all rules for %s removed (in effect now; you will be asked to save when you exit)\n", prog);
    return;
  }
  if(same(res, "stdout"))
    w = RES_STDOUT;
  else if(same(res, "cputime"))
    w = RES_CPUTIME;
  else {
    oprintf("unknown resource %s; resources: stdout cputime; nothing was removed\n", res);
    return;
  }
  for(i = 0; i < (int)sizeof(rq.prog); i++)
    rq.prog[i] = 0;
  for(i = 0; i < 15 && prog[i]; i++)
    rq.prog[i] = prog[i];
  rq.which = w;
  rq.limit = 0;                        // a limit of 0 clears that resource; the row goes when none is left
  rq.action = 0;
  rq.scope = SCOPE_PROCESS;
  r = gate(SVC_RULE_SET, (uint)&rq, sizeof(rq));
  if(r == -3)
    oprintf("no rule may name init or the Owner\n");
  else if(r < 0)
    oprintf("could not remove the rule\n");
  else
    oprintf("rule removed: %s %s (in effect now; you will be asked to save when you exit; nothing happens if it had none)\n",
            prog, res);
}

static void
cmd_revert(void)
{
  gate(SVC_RULES_STATE, 1, 0);
  save_pending = 0;
  oprintf("rules restored to the last saved state\n");
}

// Asked whenever a session ends normally: should the rule changes survive a reboot?
// "n" keeps them in effect for this boot only; revert discards them.
static void
ask_save(void)
{
  if(gate(SVC_RULES_STATE, 0, 0) > 0 &&
     confirm("Unsaved rule changes. Save them to persist after reboot"))
    save_pending = 1;
}

#ifdef OWNER_FAULT_TEST
// Test only: fault on purpose, to see the Owner restart. withpage = 1 holds an Owner pool page first.
static void
faultme(int withpage)
{
  char *pg = 0;

  if(withpage == 1)
    pg = (char*)gate(SVC_PAGE_ALLOC, 0, 0);
  oprintf("faulting on purpose%s\n", pg ? " (holding a pool page)" : "");
  if(withpage == 3)
    asm volatile("int $64" : : "a"(0));   // the system-call gate: refused at Ring 1, so this faults
  else if(withpage < 2)
    asm volatile("cli");               // privileged: a general-protection fault at Ring 1 on every platform
  else
    *(volatile int*)0x80000000 = 1;    // beyond the segment limit: faults on VMware, not on QEMU
  oprintf("not reached\n");
}
#endif

static void
cmd_killgroup(char *name)
{
  struct ps_proc *p;
  int g, gid, i, n, r;

  if(*name == 0){
    oprintf("usage: killgroup <group>   (type groups); killkind <kind> kills a whole kind\n");
    return;
  }
  if(parse_kind(name) >= 0){
    oprintf("%s is a kind, not a group; use killkind %s\n", name, name);
    return;
  }
  if(!take_snapshot())
    return;
  g = find_group(name);
  if(g < 0){
    oprintf("no group named %s; type groups\n", name);
    return;
  }
  if(snap.group[g].kind == GK_SYSTEM || snap.group[g].kind == GK_UTILITY){
    oprintf("use killkind for System and Utilities\n");
    return;
  }
  gid = snap.group[g].id;
  if(snap.group[g].nproc == 0){
    oprintf("group %s has no running processes; its memory is released when init reaps them\n", name);
    return;
  }
  oprintf("group %s (%s), processes:", snap.group[g].name, kind_name(snap.group[g].kind));
  n = clamp(snap.nproc, PS_MAXPROC);
  for(i = 0; i < n; i++){
    p = &snap.proc[i];
    if(p->gid == gid && !is(p->state, "zombie") && !is(p->state, "embryo"))
      oprintf(" %d(%s)", p->pid, p->name);
  }
  oprintf("\n");
  if(!confirm("Kill the whole group"))
    return;
  r = gate(SVC_KILLGROUP, gid, 0);
  if(r < 0)
    oprintf("no such group any more\n");
  else
    oprintf("kill requested for %d process(es), and the group takes no new forks. If it is still listed, run killgroup again\n", r);
}

static int kgid[PS_MAXGROUP];             // the groups of the kind being killed

static void
cmd_killkind(char *arg)
{
  int k, i, n, ng = 0, killed = 0, r;

  k = parse_kind(arg);
  if(k < 0){
    oprintf("usage: killkind <kind>   kinds: System  Utilities  App  Agent\n");
    return;
  }
  if(k == GK_SYSTEM){
    oprintf("refused: System holds init and the Owner; the system would stop\n");
    return;
  }
  if(!take_snapshot())
    return;
  n = clamp(snap.ngroup, PS_MAXGROUP);
  for(i = 0; i < n; i++)
    if(snap.group[i].kind == k && snap.group[i].nproc > 0)
      kgid[ng++] = snap.group[i].id;
  if(ng == 0){
    oprintf("no running processes of kind %s\n", kind_name(k));
    return;
  }
  oprintf("kind %s:", kind_name(k));
  for(i = 0; i < n; i++)
    if(snap.group[i].kind == k && snap.group[i].nproc > 0)
      oprintf(" %s(%d)", k == GK_UTILITY ? "Utilities" : snap.group[i].name, snap.group[i].nproc);
  oprintf("\n");
  if(k == GK_UTILITY)
    oprintf("this ends the shell; the system starts a new one\n");
  if(!confirm("Kill every process of this kind"))
    return;
  for(i = 0; i < ng; i++){
    r = gate(SVC_KILLGROUP, kgid[i], 0);
    if(r > 0)
      killed += r;
  }
  oprintf("kill requested for %d process(es). If a group is still listed, run killkind again\n", killed);
}

// ---- the session ----

static void
session(void)
{
  char line[64];
  char *cmd;
  int n;

  leave = 0;
  oprintf("\n=== Owner (Ring 1) ===\n");
  if(!load_block()){
    oprintf("The Owner block is not usable (never set up, or damaged). Reboot to set it up.\n");
  } else if(!rb->passset){
    oprintf("No Owner passphrase is set. Set one at the next boot.\n");
  } else if(login()){
    oprintf("Logged in. Type help.\n");
    for(;;){
      oprintf("owner> ");
      n = readline(line, sizeof(line), 0);
      if(n == -2){
        oprintf("\n");
        ask_save();
        break;
      }
      if(n < 0){
        oprintf("\nSession closed.\n");
        break;
      }
      while(n > 0 && line[n - 1] == 0x20)
        line[--n] = 0;
      cmd = line;
      while(*cmd == ' ')
        cmd++;
      if(*cmd == 0)
        continue;
      if(is(cmd, "exit") || is(cmd, "quit")){
        ask_save();
        break;
      }
      else if(is(cmd, "help"))
        oprintf("Commands: status  procs  groups  mem  ownermem  rules [program|kind]  registry  help  exit   (Ctrl-] also leaves)\n          kill <pid>   killall <program>   killgroup <group>   killkind <kind>\n          procskind <kind>   procsgroup <group>   (kinds: System, Utilities, App, Agent)\n          limit <program> <resource> <n> <action> process|program|group   unrule <program|kind> [resource]   revert\n          limit <kind> <resource> <n> <action> group   (kinds: App, Agent, Utilities; resources: cpu and memory are percents of the whole machine, cputime and stdout are counts)\n          registry   show the program registry     registry on|off   (on: a program not registered does not start)\n          install <app>   uninstall <app>   (install a bundle staged in /inbox, or remove an installed app)\n          reports [app]   latest report of installed apps, or all reports of an app (the report is the app's own claim)\n");
      else if(is(cmd, "status"))
        cmd_status();
      else if(is(cmd, "procs"))
        cmd_procs(argof(cmd, "procs"));
      else if(is(cmd, "mem"))
        cmd_mem();
      else if(is(cmd, "registry") || is(cmd, "install") || is(cmd, "uninstall"))
        cmd_registry(cmd);
      else if(is(cmd, "reports"))
        cmd_reports(cmd);
      else if(is(cmd, "rules"))
        cmd_rules_cmd(argof(cmd, "rules"));
      else if(is(cmd, "ownermem"))
        cmd_ownermem();
      else if(is(cmd, "kill"))
        cmd_kill(argof(cmd, "kill"));
      else if(is(cmd, "killall"))
        cmd_killall(argof(cmd, "killall"));
      else if(is(cmd, "groups"))
        cmd_groups();
      else if(is(cmd, "killgroup"))
        cmd_killgroup(argof(cmd, "killgroup"));
      else if(is(cmd, "killkind"))
        cmd_killkind(argof(cmd, "killkind"));
      else if(is(cmd, "procskind"))
        cmd_procskind(argof(cmd, "procskind"));
      else if(is(cmd, "procsgroup"))
        cmd_procsgroup(argof(cmd, "procsgroup"));
      else if(is(cmd, "limit"))
        cmd_limit(argof(cmd, "limit"));
      else if(is(cmd, "unrule"))
        cmd_unrule(argof(cmd, "unrule"));
      else if(is(cmd, "revert"))
        cmd_revert();
#ifdef OWNER_FAULT_TEST
      else if(is(cmd, "faultme"))
        faultme(0);
      else if(is(cmd, "faultpage"))
        faultme(1);
      else if(is(cmd, "faultmem"))
        faultme(2);
      else if(is(cmd, "faultsys"))
        faultme(3);
#endif
      else
        oprintf("Unknown command. Type help.\n");
      if(leave){
        oprintf("\nSession closed.\n");
        break;
      }
    }
  }
  oprintf("=== Owner session ended (press Enter for a shell prompt) ===\n");
}

// Calls the dispatcher must refuse, and one it must accept. The result is printed from
// this stack, so a wrongly refused stack shows as a missing line.
static void
report_checks(void)
{
  int bad = 0, i;
  struct rule_req t;
  struct kind_req kq;
  struct reg_view rv;
  int bad2;

  if(gate(SVC_PRINT, 0x80000000, 16) != -1)            bad |= 1;     // a kernel address
  if(gate(SVC_PRINT, 0xfffffff0, 0x20) != -1)          bad |= 2;     // wraps past the top
  if(gate(SVC_PRINT, 0, 100000) != -1)                 bad |= 4;     // too long
  if(gate(SVC_PRINT, 0x00080000, 16) != -1)            bad |= 8;     // the hole after the image
  if(gate(SVC_PRINT, STACK_TOP - 8, 16) != -1)         bad |= 16;    // runs past the end of the stack
  if(gate(SVC_PRINT, POOL_END - 8, 16) != -1)          bad |= 32;    // runs past the end of the pool
  if(gate(SVC_PRINT, 0x00200000, 16) != -1)            bad |= 64;    // between the stack and the pool
  if(gate(SVC_READ_BLOCK, (uint)rb, 0) != 0)           bad |= 128;   // a legitimate call
  if(gate(SVC_PAGE_FREE, 0x00001000, 0) != -1)         bad |= 256;   // not a pool address
  if(gate(SVC_PAGE_FREE, POOL_BASE + 0x1000, 0) != -1) bad |= 512;   // in the pool, not allocated
  if(gate(SVC_PAGE_FREE, POOL_BASE + 1, 0) != -1)      bad |= 1024;  // not page aligned
  if(gate(SVC_SNAPSHOT, 0x80000000, sizeof(snap)) != -1)      bad |= 2048;   // a kernel address
  if(gate(SVC_SNAPSHOT, (uint)&snap, 100) != -1)              bad |= 4096;   // the wrong size
  if(gate(SVC_SNAPSHOT, (uint)&snap + 1, sizeof(snap)) != -1) bad |= 8192;   // misaligned
  if(gate(SVC_KILL, 1, 0) != -2)                       bad |= 16384;   // pid 1 (init)
  if(gate(SVC_KILL, 0, 0) != -2)                       bad |= 32768;   // pid 0
  if(gate(SVC_KILL, gate(SVC_GETPID, 0, 0), 0) != -2)  bad |= 65536;   // the Owner itself
  if(gate(SVC_KILL, 99999, 0) != -1)                   bad |= 131072;  // no such process
  for(i = 0; i < 16; i++)
    t.prog[i] = 0;
  copy(t.prog, "init");
  t.which = 0;
  t.limit = 5;
  t.action = ACTION_KILL;
  t.scope = SCOPE_PROCESS;
  if(gate(SVC_RULE_SET, (uint)&t, sizeof(t)) != -3)       bad |= 262144;    // a rule naming init
  if(gate(SVC_RULE_SET, 0x80000000, sizeof(t)) != -1)     bad |= 524288;    // a kernel address
  if(gate(SVC_RULE_SET, (uint)&t, 7) != -1)               bad |= 1048576;   // the wrong size
  if(gate(SVC_KILLGROUP, 0, 0) != -2)                  bad |= 2097152;    // System is never killed
  if(gate(SVC_KILLGROUP, 99, 0) != -1)                 bad |= 4194304;    // no such group
  kq.kind = GK_SYSTEM;
  kq.which = KR_CPU;
  kq.limit = 5;
  kq.action = ACTION_KILL;
  if(gate(SVC_KINDRULE_SET, (uint)&kq, sizeof(kq)) != -1)  bad |= 8388608;    // System is never limited
  kq.kind = GK_APP;
  kq.limit = 101;
  if(gate(SVC_KINDRULE_SET, (uint)&kq, sizeof(kq)) != -1)  bad |= 16777216;   // more than 100 percent
  kq.limit = 5;
  if(gate(SVC_KINDRULE_SET, (uint)&kq, 7) != -1)           bad |= 33554432;   // the wrong size
  if(gate(SVC_REG_MODE, 1, 9) != -1)                      bad |= 67108864;    // a mode that does not exist
  rv.index = 0;
  if(gate(SVC_REG_ENTRY, 0x80000000, sizeof(rv)) != -1)    bad |= 134217728;   // a kernel address
  if(gate(SVC_REG_ENTRY, (uint)&rv, 7) != -1)              bad |= 268435456;   // the wrong size
  if(gate(SVC_INST_READ, 0x80000000, sizeof(struct inst_view)) != -1)  bad |= 536870912;    // a kernel address
  if(gate(SVC_INST_READ, (uint)&rv, 7) != -1)                            bad |= 1073741824;   // the wrong size
  bad2 = 0;                                                               // the checks of the services after the first variable ran out
  if(gate(SVC_INST_COMMIT, 0x80000000, sizeof(struct inst_req)) != -1)   bad2 |= 1;   // a kernel address
  if(gate(SVC_INST_COMMIT, (uint)&rv, 7) != -1)                          bad2 |= 2;   // the wrong size
  if(gate(SVC_UNINST, 0x80000000, sizeof(struct uninst_req)) != -1)   bad2 |= 4;   // a kernel address
  if(gate(SVC_UNINST, (uint)&rv, 7) != -1)                           bad2 |= 8;   // the wrong size
  if(gate(SVC_REPORT_READ, 0x80000000, sizeof(struct rep_view)) != -1)   bad2 |= 16;   // a kernel address
  if(gate(SVC_REPORT_READ, (uint)&rv, 7) != -1)                           bad2 |= 32;   // the wrong size
  if(bad == 0 && bad2 == 0)
    oprintf("\n[Owner at Ring 1] dispatcher checks: all pass\n");
  else
    oprintf("\n[Owner at Ring 1] dispatcher checks: FAIL %d %d\n", bad, bad2);
}

void
owner1_main(void)
{
  int first = 1, r;

  rb = (struct rootblock*)gate(SVC_PAGE_ALLOC, 0, 0);   // the Owner's first Owner-pool page, taken at start
  for(;;){
    gate(SVC_WAIT, 0, 0);          // sleeps until a chord arrives; the console is already taken
    if(first){
      first = 0;
      report_checks();
    }
    session();
    if(save_pending || install_pending || uninstall_pending)
      gate(SVC_BUSY, 1, 0);        // chords are ignored while the rules file is written or an app is installed or removed
    gate(SVC_CLOSE, 0, 0);         // give the keyboard and the screen back
    if(install_pending){           // the console is free: no held writers, so the file system may be used
      install_pending = 0;
      install_commit();
    }
    if(uninstall_pending){
      uninstall_pending = 0;
      uninstall_commit();
    }
    if(!save_pending)
      gate(SVC_BUSY, 0, 0);        // when the rules are saved, that step lets chords in again
    if(save_pending){              // only now may the file system be used: no held writers
      save_pending = 0;
      r = gate(SVC_RULES_SAVE, 0, 0);
      if(r == 0)
        oprintf("[Owner] rules saved to /owner/rules\n");
      else if(r == -2)
        oprintf("[Owner] rules not saved: the file system is not ready\n");
      else
        oprintf("[Owner] could not save the rules; they stay unsaved in memory\n");
      gate(SVC_BUSY, 0, 0);
    }
  }
}
