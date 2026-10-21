// SafeOS program identity. A program is known by the SHA-256 of its bytes, not by its name. exec asks
// registry_exec_check() about the file it is about to load, while it holds the file's inode lock, so the
// bytes that are hashed are the bytes that are loaded. preinstalled[] is generated at build time
// (genreg.pl). In report mode a program that is not listed runs and is reported once; in enforce mode
// exec fails.
#include "types.h"
#include "defs.h"
#include "param.h"
#include "stat.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"
#include "spinlock.h"
#include "sleeplock.h"
#include "fs.h"
#include "file.h"
#include "resource.h"
#include "psinfo.h"
#include "rootowner.h"
#include "sha256.h"

struct app_rec {                    // one installed app, as saved in /owner/apps: 200 bytes
  int   kind;                       // GK_APP or GK_AGENT
  int   reqcpu, reqout;             // what the manifest required: cputime and stdout per process; 0 = nothing
  int   pad;
  char  name[16];
  char  goal[80];
  char  report[24];
  uchar mhash[32];                  // the manifest as approved
  uchar phash[32];                  // the program: the identity exec looks for
};
typedef char app_rec_size_check[(sizeof(struct app_rec) == 200) ? 1 : -1];
#define MAXAPPS 8
static struct app_rec apps[MAXAPPS];
static int napps;                   // the first napps entries are in use
static char *app_by_hash(uchar *h); // below

static int reg_mode = REG_DEFAULT_MODE;

// The largest file xv6 can hold, so any program fits. One buffer, one lock: exec calls come from many CPUs.
static uchar hbuf[MAXFILE * BSIZE] __attribute__((aligned(4)));
static struct sleeplock hlock;           // a zero-filled sleeplock is valid and unlocked

#define NREPORTED 16
static uint reported[NREPORTED];         // the first four bytes of each hash already reported
static int  nreported;

static int
already_reported(uchar *h)               // 1 if this hash was reported before; otherwise remembers it. hlock is held
{
  uint p = h[0] | (h[1] << 8) | (h[2] << 16) | ((uint)h[3] << 24);
  int i;

  for(i = 0; i < nreported; i++)
    if(reported[i] == p)
      return 1;
  if(nreported < NREPORTED)
    reported[nreported++] = p;
  return 0;
}

static void
hex8(uchar *h, char *out)                // the first 8 hex digits of a hash
{
  static char d[] = "0123456789abcdef";
  int i;

  for(i = 0; i < 4; i++){
    out[2*i] = d[h[i] >> 4];
    out[2*i + 1] = d[h[i] & 15];
  }
  out[8] = 0;
}

int
registry_exec_check(struct inode *ip, char *name, char *regname)
{
  uchar h[32];
  char hx[9];
  uint size = ip->size;
  int i, found = -1;
  char *an;

  regname[0] = 0;                        // no registered name unless the program is found

  acquiresleep(&hlock);
  if(size > 0 && size <= sizeof(hbuf) && readi(ip, (char*)hbuf, 0, size) == (int)size){
    sha256(hbuf, size, h);
    for(i = 0; i < npreinstalled; i++)
      if(memcmp(preinstalled[i].hash, h, 32) == 0){
        found = i;
        break;
      }
  } else
    memset(h, 0, 32);                    // unreadable or too large: no identity
  if(found >= 0){
    safestrcpy(regname, preinstalled[found].name, 16);   // a registered program is known by this name, whatever it was started as
    if(strncmp(name, preinstalled[found].name, 16) != 0 && !already_reported(h))
      cprintf("[Owner policy] %s is the registered program %s (same bytes)\n", name, preinstalled[found].name);
    releasesleep(&hlock);
    return 0;
  }
  if((an = app_by_hash(h)) != 0){      // the program of an installed app: known by the app's name
    safestrcpy(regname, an, 16);
    releasesleep(&hlock);
    return 0;
  }
  hex8(h, hx);
  if(reg_mode == REG_ENFORCE){
    cprintf("[Owner policy] %s (sha256 %s...) is not registered: not started\n", name, hx);
    releasesleep(&hlock);
    return -1;
  }
  if(!already_reported(h))
    cprintf("[Owner policy] %s (sha256 %s...) is not registered: running it as an Agent (report-only)\n", name, hx);
  releasesleep(&hlock);
  return 0;
}

int
registry_mode(void)
{
  return reg_mode;
}

int
registry_set_mode(int m)
{
  if(m != REG_REPORT && m != REG_ENFORCE)
    return -1;
  reg_mode = m;
  return 0;
}

static int
pk_to_gk(int pk)
{
  return pk == PK_SYSTEM ? GK_SYSTEM : (pk == PK_APP ? GK_APP : (pk == PK_AGENT ? GK_AGENT : GK_UTILITY));
}

// Fills v for entry v->index; v->total is set even past the end (then -1 is returned).
int
registry_entry(int idx, struct reg_view *v)
{
  int j;

  v->total = npreinstalled + napps;
  v->npre = npreinstalled;
  if(idx < 0 || idx >= v->total)
    return -1;
  if(idx < npreinstalled){
    v->kind = pk_to_gk(preinstalled[idx].kind);
    memmove(v->name, preinstalled[idx].name, 16);
    memmove(v->hash, preinstalled[idx].hash, 32);
    return 0;
  }
  j = idx - npreinstalled;           // an installed app: the hash is its program's, the one exec looks for
  v->kind = apps[j].kind;
  memmove(v->name, apps[j].name, 16);
  memmove(v->hash, apps[j].phash, 32);
  return 0;
}

// The mode is saved with the rules (/owner/rules) and follows the same rule: a change applies at once, the
// Owner is asked at exit whether to save it, and revert goes back to the saved one.
static int reg_saved = REG_DEFAULT_MODE;

void
registry_snapshot(void)
{
  reg_saved = reg_mode;
}

void
registry_restore(void)
{
  reg_mode = reg_saved;
}

int
registry_dirty(void)
{
  return reg_mode != reg_saved;
}

// ---- installing: reading a staged bundle for the Owner ----
extern int begin_op_try(void);      // log.c

// Reads /inbox/<app>/ for the Owner while a session is open. It must never sleep on the log, because held
// console writers can sit inside open transactions, so it uses begin_op_try and gives up with INST_BUSY.
// The bundle must hold exactly manifest.txt and the program named like the app.
void
registry_inst_read(struct inst_view *v)
{
  struct inode *ip;
  struct dirent de;
  char app[16], path[48], nm[DIRSIZ + 1];
  uint off, n;
  int i, len, have_m = 0, have_p = 0, st = INST_OK, dirst = INST_OK;

  memmove(app, v->app, 16);
  app[15] = 0;
  v->mlen = 0;
  v->plen = 0;
  v->extra[0] = 0;
  v->manifest[0] = 0;
  v->nent = 0;
  v->status = INST_BADNAME;
  len = strlen(app);
  if(len == 0 || len > DIRSIZ)
    return;
  for(i = 0; i < len; i++)
    if(app[i] == '/')
      return;
  if(!begin_op_try()){
    v->status = INST_BUSY;
    return;
  }
  memmove(path, "/inbox/", 7);
  memmove(path + 7, app, len + 1);
  if((ip = namei(path)) == 0){
    st = INST_NOBUNDLE;
    goto out;
  }
  ilock(ip);
  if(ip->type != T_DIR){
    iunlockput(ip);
    st = INST_NOBUNDLE;
    goto out;
  }
  for(off = 2 * sizeof(de); off < ip->size; off += sizeof(de)){
    if(readi(ip, (char*)&de, off, sizeof(de)) != sizeof(de)){
      st = INST_READ;
      break;
    }
    if(de.inum == 0)
      continue;
    memmove(nm, de.name, DIRSIZ);
    nm[DIRSIZ] = 0;
    if(v->nent < 8)
      memmove(v->ent[v->nent], nm, DIRSIZ + 1);
    v->nent++;
    if(strncmp(nm, "manifest.txt", DIRSIZ) == 0)
      have_m = 1;
    else if(strncmp(nm, app, DIRSIZ) == 0)
      have_p = 1;
    else if(v->extra[0] == 0)
      memmove(v->extra, nm, DIRSIZ + 1);
  }
  iunlockput(ip);
  if(st == INST_OK){
    if(!have_m)
      st = INST_NOMANIFEST;
    else if(!have_p)
      dirst = INST_NOPROGRAM;
    else if(v->extra[0])
      dirst = INST_EXTRA;
  }
  if(st != INST_OK)
    goto out;

  memmove(path + 7 + len, "/manifest.txt", 14);
  if((ip = namei(path)) == 0){
    st = INST_NOMANIFEST;
    goto out;
  }
  ilock(ip);
  if(ip->type != T_FILE || ip->size == 0){
    iunlockput(ip);
    st = INST_NOMANIFEST;
    goto out;
  }
  if(ip->size > INST_MAXMANIFEST){
    iunlockput(ip);
    st = INST_TOOBIG;
    goto out;
  }
  n = ip->size;
  if(readi(ip, v->manifest, 0, n) != (int)n){
    iunlockput(ip);
    st = INST_READ;
    goto out;
  }
  iunlockput(ip);
  v->manifest[n] = 0;
  v->mlen = n;
  sha256((uchar*)v->manifest, n, v->mhash);
  if(dirst != INST_OK){              // something else is wrong with the bundle, but the Owner still gets the manifest
    st = dirst;
    goto out;
  }

  path[7 + len] = '/';
  memmove(path + 8 + len, app, len + 1);
  if((ip = namei(path)) == 0){
    st = INST_NOPROGRAM;
    goto out;
  }
  ilock(ip);
  if(ip->type != T_FILE || ip->size == 0){
    iunlockput(ip);
    st = INST_NOPROGRAM;
    goto out;
  }
  if(ip->size > sizeof(hbuf)){
    iunlockput(ip);
    st = INST_TOOBIG;
    goto out;
  }
  n = ip->size;
  acquiresleep(&hlock);              // the order is the inode, then the hash lock, as in exec; no transaction is opened under it
  if(readi(ip, (char*)hbuf, 0, n) == (int)n){
    sha256(hbuf, n, v->phash);
    v->plen = n;
  } else
    st = INST_READ;
  releasesleep(&hlock);
  iunlockput(ip);
out:
  end_op();
  v->status = st;
}

// ---- installed apps ----
// The Owner approves an install in a session; once the session has closed it sends the approved request here. The bundle
// is copied into /apps/<app>/, the copy is hashed and compared with what the Owner approved, the app's requirements become
// rules on its name, and the record is written to /owner/apps. Anything that goes wrong undoes all of it.
extern struct inode *create(char *path, short type, short major, short minor);   // sysfile.c
extern volatile int owner_fs_ready;                                              // rootguard.c

struct apps_hdr {
  uint magic;
  uint version;
  uint count;
  uint rowsize;
  uint checksum;
  uint pad[3];
};
typedef char apps_hdr_size_check[(sizeof(struct apps_hdr) == 32) ? 1 : -1];
#define APPS_MAGIC     0x41505031      // "APP1"
#define APPS_FILE_SIZE (sizeof(struct apps_hdr) + MAXAPPS * sizeof(struct app_rec))
static uchar apps_buf[APPS_FILE_SIZE] __attribute__((aligned(4)));
static uchar cbuf[1024] __attribute__((aligned(4)));    // the install copies through this buffer: only the Owner installs, one app at a time

static uint
apps_sum(uchar *p, uint n)
{
  uint s = 0x9e3779b9, i;

  for(i = 0; i < n; i++)
    s = ((s << 5) | (s >> 27)) ^ p[i];
  return s;
}

static char*
app_by_hash(uchar *h)
{
  int i;

  for(i = 0; i < napps; i++)
    if(memcmp(apps[i].phash, h, 32) == 0)
      return apps[i].name;
  return 0;
}

static int
app_find(char *name)
{
  int i;

  for(i = 0; i < napps; i++)
    if(strncmp(apps[i].name, name, 16) == 0)
      return i;
  return -1;
}

int
registry_app_kind(char *name)       // the kind the manifest declared: PK_APP or PK_AGENT; PK_AGENT for any other name
{
  int i = app_find(name);

  if(i >= 0 && apps[i].kind == GK_APP)
    return PK_APP;
  return PK_AGENT;
}

static void
pathcat(char *out, char *a, char *b, char *c, char *e)    // out = a + b + c + e; every path here is under 48 bytes
{
  int n = 0;

  while(*a)
    out[n++] = *a++;
  while(*b)
    out[n++] = *b++;
  while(*c)
    out[n++] = *c++;
  while(*e)
    out[n++] = *e++;
  out[n] = 0;
}

// ---- the guard on /apps ----
// The inodes that programs may read and run but not change: /apps, each installed app's directory, its manifest and its
// program. They are found by name here, in the Owner's own context, and then protected by number in rootguard.c, so no
// other name for them gets round the guard.
static uint prot[48];
static int nprot;

// The report area of each installed app: /apps/<app>/report/status.txt, one file of at most REPORT_MAX bytes. Only the processes
// of the app's own group, and the Owner, reach the directory or the file. The kernel notes every write to it.
#define REPORT_MAX 4096
#define REPORT_HDR 64                // the kernel's header at the start of a report file; the app's text follows
#define REPORT_REC 256               // one record: the 64-byte header and 192 bytes for the app's text and a newline
#define REPORT_TXT 191               // the longest text an app may report
struct rep_rec {
  uint dirino, fileino;             // the report directory and its file
  char app[16];
  int  kind;                        // GK_APP or GK_AGENT: the group that may write must be of this kind
};
static struct rep_rec reps[MAXAPPS];
static int nreps;
static struct spinlock replock;
extern int proc_in_group(char *name, int kind);   // proc.c
extern uint ticks;
extern int proc_group_name(char *name, int *kind);   // proc.c
extern struct inode *iget_report(uint inum);          // fs.c

// A record's 64-byte header, written only by the kernel and ended by a newline:
//   SAFEOS REPORT <app, padded to 14> tick=<10 digits> pid=<5 digits> n=<6 digits>
static void
rep_digits(char *h, int at, uint v, int digits)
{
  uint max = 1;
  int i;

  for(i = 0; i < digits; i++)
    max *= 10;
  if(v >= max)
    v = max - 1;                         // a number that does not fit stops at all nines
  for(i = digits - 1; i >= 0; i--){
    h[at + i] = '0' + v % 10;
    v /= 10;
  }
}

static void
rep_fmt(char *h, char *app, uint tick, int pid, uint n)
{
  static const char magic[] = "SAFEOS REPORT ";
  static const char t1[] = " tick=", t2[] = " pid=", t3[] = " n=";
  int i, end = 0;

  for(i = 0; i < 14; i++)
    h[i] = magic[i];
  for(i = 0; i < 14; i++){
    if(!end && app[i] == 0)
      end = 1;
    h[14 + i] = end ? ' ' : app[i];
  }
  for(i = 0; i < 6; i++)
    h[28 + i] = t1[i];
  rep_digits(h, 34, tick, 10);
  for(i = 0; i < 5; i++)
    h[44 + i] = t2[i];
  rep_digits(h, 49, pid < 0 ? 0 : pid, 5);
  for(i = 0; i < 3; i++)
    h[54 + i] = t3[i];
  rep_digits(h, 57, n, 6);
  h[63] = '\n';
}

// A report file that is not a whole number of records, or is over 4096 bytes, starts again empty. Boot only.
static void
rep_fit(char *path)
{
  struct inode *ip;

  begin_op();
  ip = namei(path);
  if(ip){
    ilock(ip);
    if(ip->size % REPORT_REC != 0 || ip->size > REPORT_MAX){
      ip->size = 0;
      iupdate(ip);
    }
    iunlockput(ip);
  }
  end_op();
}

int
apps_guard_has(uint inum)
{
  int i;

  for(i = 0; i < nprot; i++)
    if(prot[i] == inum)
      return 1;
  return 0;
}

static uint
inum_of(char *path)                  // the inode number of a path, 0 if there is none
{
  struct inode *ip;
  uint n = 0;

  begin_op();
  ip = namei(path);
  if(ip){
    n = ip->inum;
    iput(ip);
  }
  end_op();
  return n;
}

static void
prot_add(uint n)
{
  if(n != 0 && nprot < 48){
    prot[nprot] = n;                 // the entry is filled in before it is counted
    nprot++;
  }
}

static void
apps_guard_rebuild(void)             // /apps, each app's directory, files and report directory; and the record of its report file
{
  uint t[48];
  struct rep_rec nrp[MAXAPPS];
  char p[48];
  int i, n = 0, nr = 0, k;
  uint v, rd, rf;

  memset(nrp, 0, sizeof(nrp));
  if((v = inum_of("/apps")) != 0)
    t[n++] = v;
  for(i = 0; i < napps && n + 4 <= 48; i++){
    pathcat(p, "/apps/", apps[i].name, "", "");
    if((v = inum_of(p)) != 0)
      t[n++] = v;
    pathcat(p, "/apps/", apps[i].name, "/manifest.txt", "");
    if((v = inum_of(p)) != 0)
      t[n++] = v;
    pathcat(p, "/apps/", apps[i].name, "/", apps[i].name);
    if((v = inum_of(p)) != 0)
      t[n++] = v;
    pathcat(p, "/apps/", apps[i].name, "/report", "");
    rd = inum_of(p);
    pathcat(p, "/apps/", apps[i].name, "/report/status.txt", "");
    rf = inum_of(p);
    if(rd != 0)
      t[n++] = rd;                   // nothing can be made, removed or linked inside the report directory
    if(rd != 0 && rf != 0){          // the report file itself is not sealed: the app's group may write it
      nrp[nr].dirino = rd;
      nrp[nr].fileino = rf;
      nrp[nr].kind = apps[i].kind;
      safestrcpy(nrp[nr].app, apps[i].name, sizeof(nrp[nr].app));
      nr++;
    }
  }
  acquire(&replock);
  memmove(reps, nrp, sizeof(reps));
  nreps = nr;
  release(&replock);
  for(k = 0; k < n; k++)
    prot[k] = t[k];
  nprot = n;
}

// Remove a file or an empty directory, as sys_unlink does. 0, or -1.
static int
kunlink(char *path)
{
  struct inode *ip, *dp;
  struct dirent de;
  char name[DIRSIZ];
  uint off, o2;

  begin_op();
  if((dp = nameiparent(path, name)) == 0){
    end_op();
    return -1;
  }
  ilock(dp);
  if(namecmp(name, ".") == 0 || namecmp(name, "..") == 0){
    iunlockput(dp);
    end_op();
    return -1;
  }
  ip = dirlookup(dp, name, &off);
  if(ip == 0){
    iunlockput(dp);
    end_op();
    return -1;
  }
  ilock(ip);
  if(ip->nlink < 1)
    panic("kunlink: nlink < 1");
  if(ip->type == T_DIR){
    for(o2 = 2 * sizeof(de); o2 < ip->size; o2 += sizeof(de)){
      if(readi(ip, (char*)&de, o2, sizeof(de)) != sizeof(de))
        panic("kunlink: readi");
      if(de.inum != 0){                // not empty
        iunlockput(ip);
        iunlockput(dp);
        end_op();
        return -1;
      }
    }
  }
  memset(&de, 0, sizeof(de));
  if(writei(dp, (char*)&de, off, sizeof(de)) != sizeof(de))
    panic("kunlink: writei");
  if(ip->type == T_DIR){
    dp->nlink--;
    iupdate(dp);
  }
  iunlockput(dp);
  ip->nlink--;
  iupdate(ip);
  iunlockput(ip);
  end_op();
  return 0;
}

static int
kmkdir(char *path)
{
  struct inode *ip;

  begin_op();
  ip = create(path, T_DIR, 0, 0);
  if(ip == 0){
    end_op();
    return -1;
  }
  iunlockput(ip);
  end_op();
  return 0;
}

static int
kmkfile(char *path)
{
  struct inode *ip;

  begin_op();
  ip = create(path, T_FILE, 0, 0);
  if(ip == 0){
    end_op();
    return -1;
  }
  iunlockput(ip);
  end_op();
  return 0;
}

// Copy a file, 1 KB per transaction. No hash lock is held. 0, or -1.
static int
kcopy(char *src, char *dst)
{
  struct inode *sp, *dp;
  uint off = 0, size;
  int n, r;

  begin_op();
  sp = namei(src);
  if(sp == 0){
    end_op();
    return -1;
  }
  dp = create(dst, T_FILE, 0, 0);       // returned locked
  if(dp == 0){
    iput(sp);
    end_op();
    return -1;
  }
  iunlock(dp);
  end_op();
  ilock(sp);
  size = sp->size;
  iunlock(sp);
  while(off < size){
    n = size - off > 1024 ? 1024 : size - off;
    ilock(sp);
    n = readi(sp, (char*)cbuf, off, n);
    iunlock(sp);
    if(n <= 0)
      break;
    begin_op();
    ilock(dp);
    r = writei(dp, (char*)cbuf, off, n);
    iunlock(dp);
    end_op();
    if(r != n)
      break;
    off += n;
  }
  begin_op();
  iput(sp);
  iput(dp);
  end_op();
  return off == size ? 0 : -1;
}

// SHA-256 of a file. The inode is locked first and the hash lock only around the read and the hash, with no transaction
// opened while it is held, so an exec that waits for the lock cannot be waiting for the log. 0, or -1.
static int
khash(char *path, uchar *out)
{
  struct inode *ip;
  uint size;
  int n;

  begin_op();
  ip = namei(path);
  end_op();
  if(ip == 0)
    return -1;
  ilock(ip);
  size = ip->size;
  if(ip->type != T_FILE || size == 0 || size > sizeof(hbuf)){
    iunlock(ip);
    begin_op();
    iput(ip);
    end_op();
    return -1;
  }
  acquiresleep(&hlock);
  n = readi(ip, (char*)hbuf, 0, size);
  if(n == (int)size)
    sha256(hbuf, size, out);
  releasesleep(&hlock);
  iunlock(ip);
  begin_op();
  iput(ip);
  end_op();
  return n == (int)size ? 0 : -1;
}

// Remove /apps/<app>/ with the two files an install puts in it. 0 if the directory is gone.
static int
remove_app_tree(char *app)
{
  char d[48], m[48], p[48], r[48], s[48];

  pathcat(d, "/apps/", app, "", "");
  pathcat(m, "/apps/", app, "/manifest.txt", "");
  pathcat(p, "/apps/", app, "/", app);
  pathcat(r, "/apps/", app, "/report", "");
  pathcat(s, "/apps/", app, "/report/status.txt", "");
  kunlink(s);
  kunlink(r);
  kunlink(m);
  kunlink(p);
  return kunlink(d);
}

static int
apps_save(void)                     // write /owner/apps: one transaction, so a power cut leaves the old file or the new one
{
  struct inode *ip;
  struct apps_hdr *h = (struct apps_hdr*)apps_buf;
  uchar *rows = apps_buf + sizeof(struct apps_hdr);
  int n;

  memset(apps_buf, 0, sizeof(apps_buf));
  memmove(rows, apps, sizeof(apps));
  h->magic = APPS_MAGIC;
  h->version = 1;
  h->count = napps;
  h->rowsize = sizeof(struct app_rec);
  h->checksum = apps_sum(rows, sizeof(apps));
  begin_op();
  ip = namei("/owner/apps");
  if(ip == 0){
    ip = create("/owner/apps", T_FILE, 0, 0);      // returned locked
    if(ip == 0){
      end_op();
      return -1;
    }
  } else {
    ilock(ip);
    if(ip->type != T_FILE){
      iunlockput(ip);
      end_op();
      return -1;
    }
  }
  n = writei(ip, (char*)apps_buf, 0, APPS_FILE_SIZE);
  iunlockput(ip);
  end_op();
  return n == (int)APPS_FILE_SIZE ? 0 : -1;
}

static int
apps_apply_rules(struct app_rec *a)    // the manifest's requirements become per-process kill rules on the app's name
{
  int r = 0;

  if(a->reqcpu > 0 && rule_set(a->name, RES_CPUTIME, a->reqcpu, ACTION_KILL, SCOPE_GROUP) < 0)
    r = -1;
  if(a->reqout > 0 && rule_set(a->name, RES_STDOUT, a->reqout, ACTION_KILL | ACTION_DENY, SCOPE_GROUP) < 0)
    r = -1;
  return r;
}

static void
apps_cleanup(void)                  // remove what is in /apps without a record: the rest of an install that was cut short
{
  struct inode *dp;
  struct dirent de;
  char names[16][DIRSIZ + 1];
  int n = 0, i, j;
  uint off;

  begin_op();
  dp = namei("/apps");
  if(dp == 0){
    end_op();
    return;
  }
  ilock(dp);
  for(off = 2 * sizeof(de); off < dp->size && n < 16; off += sizeof(de)){
    if(readi(dp, (char*)&de, off, sizeof(de)) != sizeof(de))
      break;
    if(de.inum == 0)
      continue;
    memmove(names[n], de.name, DIRSIZ);
    names[n][DIRSIZ] = 0;
    n++;
  }
  iunlockput(dp);
  end_op();
  for(i = 0; i < n; i++){
    for(j = 0; j < napps; j++)
      if(strncmp(names[i], apps[j].name, DIRSIZ) == 0)
        break;
    if(j < napps)
      continue;
    if(remove_app_tree(names[i]) == 0)
      cprintf("[Owner] removed /apps/%s: it was not an installed app\n", names[i]);
    else
      cprintf("[Owner] /apps/%s is not an installed app and could not be removed\n", names[i]);
  }
}

// Boot, from owner_fs_up, before the guard is on and before any program runs.
void
registry_apps_boot(void)
{
  struct inode *ip;
  struct apps_hdr *h = (struct apps_hdr*)apps_buf;
  uchar *rows = apps_buf + sizeof(struct apps_hdr);
  char rp[48], sf[48];
  int n = -1, i, exists = 0, ok = 0;

  initlock(&replock, "report");
  begin_op();
  ip = namei("/owner/apps");
  if(ip != 0){
    exists = 1;
    ilock(ip);
    if(ip->type == T_FILE && ip->size == APPS_FILE_SIZE)
      n = readi(ip, (char*)apps_buf, 0, APPS_FILE_SIZE);
    iunlockput(ip);
  }
  end_op();
  if(n == (int)APPS_FILE_SIZE && h->magic == APPS_MAGIC && h->version == 1 && h->rowsize == sizeof(struct app_rec) &&
     h->count <= MAXAPPS && h->checksum == apps_sum(rows, sizeof(apps)))
    ok = 1;
  if(ok){
    memmove(apps, rows, sizeof(apps));
    napps = h->count;
    for(i = 0; i < napps; i++)
      if(apps[i].name[0] == 0 || apps[i].name[15] != 0 || (apps[i].kind != GK_APP && apps[i].kind != GK_AGENT))
        ok = 0;
  }
  if(!ok){
    memset(apps, 0, sizeof(apps));
    napps = 0;
    if(exists){                        // a damaged record must not make us delete installed apps
      cprintf("[Owner] /owner/apps is damaged: no installed apps are loaded, and /apps is left alone\n");
      apps_guard_rebuild();            // only /apps itself can be protected without a record
      return;
    }
    apps_cleanup();                    // no record at all: whatever /apps holds is not an installed app
    apps_guard_rebuild();
    return;
  }
  for(i = 0; i < napps; i++){            // an app installed before reports existed gets its report directory now
    pathcat(rp, "/apps/", apps[i].name, "/report", "");
    if(inum_of(rp) == 0){
      pathcat(sf, "/apps/", apps[i].name, "/report/status.txt", "");
      if(kmkdir(rp) < 0 || kmkfile(sf) < 0)
        cprintf("[Owner] could not make the report directory of %s\n", apps[i].name);
    }
  }
  for(i = 0; i < napps; i++){            // a report file from the earlier layout is not a whole number of records: it starts empty
    pathcat(sf, "/apps/", apps[i].name, "/report/status.txt", "");
    rep_fit(sf);
  }
  for(i = 0; i < napps; i++)
    if(apps_apply_rules(&apps[i]) < 0)
      cprintf("[Owner] the rule table has no room for the requirements of %s\n", apps[i].name);
  if(napps > 0){
    rules_snapshot();                  // the rules are clean at boot: these ones are not an unsaved change
    cprintf("[Owner] %d installed app(s) loaded from /owner/apps\n", napps);
  }
  apps_cleanup();
  apps_guard_rebuild();
}

void
registry_inst_commit(struct inst_req *q)
{
  char app[16], d[48], sm[48], sp[48], mp[48], pp[48], rp[48], sf[48];
  uchar hm[32], hp[32];
  struct inode *ip;
  struct app_rec *a;
  int i, len;

  memmove(app, q->app, 16);
  app[15] = 0;
  len = strlen(app);
  q->status = INST_C_BAD;
  if(len == 0 || len > DIRSIZ || (q->kind != GK_APP && q->kind != GK_AGENT))
    return;
  for(i = 0; i < len; i++)
    if(app[i] == '/' || app[i] < 33)
      return;
  if(!owner_fs_ready){
    q->status = INST_C_NOFS;
    return;
  }
  if(app_find(app) >= 0){
    q->status = INST_C_EXISTS;
    return;
  }
  if(napps >= MAXAPPS){
    q->status = INST_C_FULL;
    return;
  }
  pathcat(d, "/apps/", app, "", "");
  pathcat(sm, "/inbox/", app, "/manifest.txt", "");
  pathcat(sp, "/inbox/", app, "/", app);
  pathcat(mp, "/apps/", app, "/manifest.txt", "");
  pathcat(pp, "/apps/", app, "/", app);
  pathcat(rp, "/apps/", app, "/report", "");
  pathcat(sf, "/apps/", app, "/report/status.txt", "");
  begin_op();
  ip = namei(d);                        // something already called /apps/<app>: leave it alone
  if(ip != 0)
    iput(ip);
  end_op();
  if(ip != 0 || kmkdir(d) < 0){
    q->status = INST_C_EXISTS;
    return;
  }
  prot_add(inum_of(d));                 // from now on nothing but the Owner can add to the directory
  q->status = INST_C_COPY;
  if(kcopy(sm, mp) < 0)
    goto undo;
  prot_add(inum_of(mp));
  if(kcopy(sp, pp) < 0)
    goto undo;
  prot_add(inum_of(pp));
  if(khash(mp, hm) < 0 || khash(pp, hp) < 0)
    goto undo;
  q->status = INST_C_CHANGED;
  if(memcmp(hm, q->mhash, 32) != 0 || memcmp(hp, q->phash, 32) != 0)
    goto undo;
  q->status = INST_C_COPY;
  if(kmkdir(rp) < 0)                    // the app's report directory and its one file: only the app's group and the Owner reach them
    goto undo;
  prot_add(inum_of(rp));
  if(kmkfile(sf) < 0)
    goto undo;
  a = &apps[napps];
  memset(a, 0, sizeof(*a));
  a->kind = q->kind;
  a->reqcpu = q->reqcpu;
  a->reqout = q->reqout;
  safestrcpy(a->name, app, sizeof(a->name));
  memmove(a->goal, q->goal, sizeof(a->goal));
  a->goal[sizeof(a->goal) - 1] = 0;
  memmove(a->report, q->report, sizeof(a->report));
  a->report[sizeof(a->report) - 1] = 0;
  memmove(a->mhash, hm, 32);
  memmove(a->phash, hp, 32);
  q->status = INST_C_RULES;
  if(apps_apply_rules(a) < 0){
    rule_remove(app);
    memset(a, 0, sizeof(*a));
    goto undo;
  }
  napps++;
  q->status = INST_C_RECORD;
  if(apps_save() < 0){
    napps--;
    memset(&apps[napps], 0, sizeof(apps[napps]));
    rule_remove(app);
    goto undo;
  }
  q->status = INST_C_OK;
  apps_guard_rebuild();
  return;

undo:
  remove_app_tree(app);                 // nothing of the install stays
  apps_guard_rebuild();
}

// ---- uninstalling ----
extern int group_find(char *name, int kind);      // proc.c
extern int kill_group(int gid);                   // proc.c
extern int rules_save_file(void);                 // rootrules.c

// The Owner approved an uninstall in a session; once the session has closed it comes here. Order matters: the record goes
// first, so no new launch is registered; then the rules, the processes, and the files. If the record cannot be written,
// nothing at all has changed.
void
registry_uninstall(struct uninst_req *q)
{
  char app[16];
  struct app_rec old;
  int i, len, gid, kind, was_dirty;

  memmove(app, q->app, 16);
  app[15] = 0;
  len = strlen(app);
  q->status = UNINST_BAD;
  if(len == 0 || len > DIRSIZ)
    return;
  for(i = 0; i < len; i++)
    if(app[i] == '/' || app[i] < 33)
      return;
  if(!owner_fs_ready){
    q->status = UNINST_NOFS;
    return;
  }
  i = app_find(app);
  if(i < 0){
    q->status = UNINST_NOAPP;
    return;
  }
  memmove(&old, &apps[i], sizeof(old));
  kind = old.kind;
  memmove(&apps[i], &apps[i + 1], (napps - i - 1) * sizeof(apps[0]));
  napps--;
  memset(&apps[napps], 0, sizeof(apps[napps]));
  if(apps_save() < 0){                  // the record could not be written: put everything back
    memmove(&apps[i + 1], &apps[i], (napps - i) * sizeof(apps[0]));
    memmove(&apps[i], &old, sizeof(old));
    napps++;
    q->status = UNINST_RECORD;
    return;
  }
  rule_remove(app);                     // the app's rules
  rule_remove_saved(app);               // and from the saved copy, so a revert cannot bring them back
  was_dirty = apps_rules_dirty() || kindrules_dirty() || registry_dirty();
  if(!was_dirty && rules_save_file() == 0)
    rules_snapshot();                   // no other unsaved change: the saved rules file loses them too
  gid = group_find(app, kind);
  if(gid >= 3)
    kill_group(gid);                    // its processes end; running programs hold their own copy of the code
  q->status = remove_app_tree(app) == 0 ? UNINST_OK : UNINST_FILES;
  apps_guard_rebuild();
}

// ---- the report files, as the guard and filewrite see them ----
int
apps_report_hidden(uint inum)        // 1 if inum is an app's report directory or file: only the Owner reaches them by name
{
  int k;

  for(k = 0; k < nreps; k++)
    if(reps[k].dirino == inum || reps[k].fileino == inum)
      return 1;
  return 0;
}

int
apps_report_is(uint inum)
{
  int k;

  for(k = 0; k < nreps; k++)
    if(reps[k].dirino == inum || reps[k].fileino == inum)
      return 1;
  return 0;
}


// ---- the report calls ----
// An installed app keeps a log of at most 16 reports in /apps/<app>/report/status.txt and reaches it only through the calls below:
// plain open refuses the file, for the app too. A record is 256 bytes at a multiple of 256: a 64-byte header the kernel writes
// (app, tick, pid, record number) and 192 bytes for the app's text. The record number is the file's size over 256, so nothing else
// is kept. The file is found by its inode number, which no path or name can stand in for.
static uint
rep_file_of_caller(char *name)       // the inode number of the caller's report file, 0 if the caller is in no installed app's group
{
  char gn[16];
  int kind, k;
  uint ino = 0;

  if(!proc_group_name(gn, &kind))
    return 0;
  acquire(&replock);
  for(k = 0; k < nreps; k++)
    if(reps[k].kind == kind && strncmp(reps[k].app, gn, 16) == 0){
      ino = reps[k].fileino;
      safestrcpy(name, reps[k].app, 16);
      break;
    }
  release(&replock);
  return ino;
}

int
apps_report_write(char *text, int n)   // 0, -1 not an app, -2 the log is full, -3 the text is too long, -4 the file is damaged
{
  char app[16], rec[REPORT_REC];
  struct inode *ip;
  uint ino, size;
  int i, r, c;

  if(n < 0 || n > REPORT_TXT)
    return -3;
  if((ino = rep_file_of_caller(app)) == 0)
    return -1;
  begin_op();
  ip = iget_report(ino);
  ilock(ip);
  size = ip->size;
  if(size % REPORT_REC != 0 || size > REPORT_MAX){
    r = -4;                              // not a whole number of records: the next boot empties it
  } else if(size >= REPORT_MAX){
    r = -2;
  } else {
    rep_fmt(rec, app, ticks, myproc() ? myproc()->pid : 0, size / REPORT_REC + 1);
    for(i = 0; i < REPORT_TXT; i++){     // the text, then spaces, and a newline at the end of the record
      c = i < n ? (unsigned char)text[i] : ' ';
      rec[REPORT_HDR + i] = (c >= 32 && c < 127) ? c : '?';
    }
    rec[REPORT_REC - 1] = '\n';
    r = writei(ip, rec, size, REPORT_REC) == REPORT_REC ? 0 : -4;
  }
  iunlock(ip);
  iput(ip);
  end_op();
  return r;
}

int
apps_report_read(char *buf, int max)   // the caller's own log; the bytes copied, or -1 if the caller is not an app
{
  char app[16];
  struct inode *ip;
  uint ino;
  int n;

  if((ino = rep_file_of_caller(app)) == 0)
    return -1;
  begin_op();
  ip = iget_report(ino);
  ilock(ip);
  n = ip->size > (uint)max ? max : (int)ip->size;
  if(n > 0)
    n = readi(ip, buf, 0, n);
  iunlock(ip);
  iput(ip);
  end_op();
  return n < 0 ? -1 : n;
}

int
apps_report_clear(void)                // 0, or -1 if the caller is not an app
{
  char app[16];
  struct inode *ip;
  uint ino;

  if((ino = rep_file_of_caller(app)) == 0)
    return -1;
  begin_op();
  ip = iget_report(ino);
  ilock(ip);
  ip->size = 0;                        // the blocks stay with the file, so the next report reuses them
  iupdate(ip);
  iunlock(ip);
  iput(ip);
  end_op();
  return 0;
}

// For the Owner's reports command: one record of an app's log, never sleeping on the log, so a session cannot freeze: with no room
// it answers REP_BUSY.
void
registry_report_read(struct rep_view *v)
{
  char app[16];
  struct rep_rec r;
  struct inode *ip;
  int k, idx, recno, nrec;
  uint size;

  memmove(app, v->app, 16);
  app[15] = 0;
  idx = v->index;
  recno = v->recno;
  v->status = REP_NOAPP;
  v->nrec = 0;
  v->name[0] = 0;
  v->rec[0] = 0;
  acquire(&replock);
  v->total = nreps;
  if(idx >= 0){
    k = idx;
  } else {
    for(k = 0; k < nreps; k++)
      if(strncmp(reps[k].app, app, 16) == 0)
        break;
  }
  if(k < 0 || k >= nreps){
    release(&replock);
    return;
  }
  memmove(&r, &reps[k], sizeof(r));
  release(&replock);
  memmove(v->name, r.app, 16);
  v->name[15] = 0;
  v->now = ticks;
  if(!begin_op_try()){
    v->status = REP_BUSY;
    return;
  }
  ip = iget_report(r.fileino);
  ilock(ip);
  size = ip->size;
  nrec = size / REPORT_REC;
  v->nrec = nrec;
  if(recno == -2)
    recno = nrec - 1;
  v->status = REP_OK;
  if(recno >= 0 && recno < nrec && readi(ip, v->rec, recno * REPORT_REC, REPORT_REC) != REPORT_REC)
    v->status = REP_READ;
  iunlock(ip);
  iput(ip);
  end_op();
}

// ---- the rows of installed apps are the manifests', and are never saved ----
static char appnames[MAXAPPS][16];

static int
apps_names(void)                       // the installed apps' names, in appnames; how many
{
  int i;

  for(i = 0; i < napps; i++)
    safestrcpy(appnames[i], apps[i].name, 16);
  return napps;
}

int
apps_rules_dirty(void)
{
  int n = apps_names();

  return rules_dirty_except(appnames, n);
}

void
apps_rules_export(struct program_policy *out)
{
  int n = apps_names();

  rules_export_except(out, appnames, n);
}

void
registry_apps_reapply(void)            // after a revert: remove each installed app's rows, whatever they hold, and apply its manifest again
{
  int i;

  for(i = 0; i < napps; i++){
    rule_remove(apps[i].name);
    if(apps_apply_rules(&apps[i]) < 0)
      cprintf("[Owner] the rule table has no room for the requirements of %s\n", apps[i].name);
  }
}

// ---- the guard on /bin and /init ----
// /bin and everything in it can be read and run, but not changed: no name is made, removed or linked inside it, its files
// cannot be written, emptied or given a second name, and /bin itself cannot be removed. /init, which exists only in the
// root and is what the kernel starts first, is sealed the same way, and the root names bin, init and sh cannot be removed
// or linked (the stock xv6 kernel runs sh from the root). The inodes are found by reading the directory at boot, before
// any program runs, and are then protected by number, so a root name such as /sh, which is the same inode as /bin/sh, is
// covered too. The Owner is exempt, and make APPS_OPEN=1 leaves all of it open.
#define NBINPROT 64
static uint bin_dir;                  // the inode of /bin; 0 = there is none
static uint bin_ino[NBINPROT];        // the inodes of the entries in it, and /init
static int nbin;

int
bin_guard_dir(uint inum)
{
  return bin_dir != 0 && inum == bin_dir;
}

int
bin_guard_has(uint inum)              // 1 if the inode is /bin, something in it, or /init
{
  int i;

  if(bin_dir == 0)
    return 0;
  if(inum == bin_dir)
    return 1;
  for(i = 0; i < nbin; i++)
    if(bin_ino[i] == inum)
      return 1;
  return 0;
}

void
bin_guard_boot(void)
{
  struct inode *ip, *ii;
  struct dirent de;
  uint off, dirino;
  int over = 0;

  bin_dir = 0;
  nbin = 0;
  begin_op();
  ip = namei("/bin");
  if(ip == 0){
    end_op();
    cprintf("[Owner] there is no /bin: nothing is sealed\n");
    return;
  }
  ilock(ip);
  if(ip->type != T_DIR){
    iunlockput(ip);
    end_op();
    return;
  }
  dirino = ip->inum;
  for(off = 2 * sizeof(de); off < ip->size; off += sizeof(de)){
    if(readi(ip, (char*)&de, off, sizeof(de)) != sizeof(de))
      break;
    if(de.inum == 0)
      continue;
    if(nbin < NBINPROT)
      bin_ino[nbin++] = de.inum;
    else
      over = 1;
  }
  iunlockput(ip);
  if((ii = namei("/init")) != 0){     // /init is not in /bin, but the first process runs it
    if(nbin < NBINPROT)
      bin_ino[nbin++] = ii->inum;
    else
      over = 1;
    iput(ii);
  }
  bin_dir = dirino;                   // set last: the guard looks at the table only once the directory is known
  end_op();
  if(over)
    cprintf("[Owner] /bin holds more than %d entries: the rest are not sealed\n", NBINPROT);
}
