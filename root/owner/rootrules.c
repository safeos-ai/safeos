// SafeOS Owner rules file: /owner/rules, a fixed-size file (header plus all rows).
// Loading runs at boot, before the /owner guard is switched on. Saving runs in the
// Owner process after a session has released the console, never during one.
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
#include "rootowner.h"

#define RULES_MAGIC   0x52554C31     // "RUL1"
#define RULES_VERSION 3              // 3: the limits per kind include cputime and stdout; versions 1 and 2 still load

extern struct inode *create(char *path, short type, short major, short minor);   // sysfile.c

struct rules_hdr {
  uint magic;
  uint version;
  uint nres;         // NRESOURCE when written
  uint rowsize;      // sizeof(struct program_policy) when written
  uint nrows;        // RULE_MAX when written
  uint checksum;     // over the rows
  uint pad[2];
};
typedef char rules_hdr_size_check[(sizeof(struct rules_hdr) == 32) ? 1 : -1];

#define RULES_ROWS_BYTES (RULE_MAX * sizeof(struct program_policy))
#define RULES_FILE_SIZE_V1 (sizeof(struct rules_hdr) + RULES_ROWS_BYTES)
#define KIND_BYTES         (NKINDRULE * sizeof(struct kind_rules))
#define RULES_FILE_SIZE    (RULES_FILE_SIZE_V1 + KIND_BYTES)
#define KIND_BYTES_V2      (NKINDRULE * 16)     // version 2: only cpu and memory per kind
#define RULES_FILE_SIZE_V2 (RULES_FILE_SIZE_V1 + KIND_BYTES_V2)
#define KIND_BYTES_V2      (NKINDRULE * 16)     // version 2: only cpu and memory per kind
#define RULES_FILE_SIZE_V2 (RULES_FILE_SIZE_V1 + KIND_BYTES_V2)

static uchar rules_buf[RULES_FILE_SIZE] __attribute__((aligned(4)));   // used by one caller at a time

static uint
rules_sum(uchar *p, uint n)
{
  uint s = 0x9e3779b9, i;

  for(i = 0; i < n; i++)
    s = ((s << 5) | (s >> 27)) ^ p[i];
  return s;
}

// 1 = loaded, 0 = no file, -1 = file present but unusable
static int
rules_load_file(void)
{
  struct inode *ip;
  struct rules_hdr *h = (struct rules_hdr*)rules_buf;
  uchar *rows = rules_buf + sizeof(struct rules_hdr);
  uchar *kb = rules_buf + RULES_FILE_SIZE_V1;
  struct kind_rules cur[NKINDRULE];
  int *o;
  uint sz;
  int n, k;

  begin_op();
  ip = namei("/owner/rules");
  if(ip == 0){
    end_op();
    return 0;
  }
  ilock(ip);
  if(ip->type != T_FILE || (ip->size != RULES_FILE_SIZE && ip->size != RULES_FILE_SIZE_V2 &&
                            ip->size != RULES_FILE_SIZE_V1)){
    iunlockput(ip);
    end_op();
    return -1;
  }
  sz = ip->size;
  n = readi(ip, (char*)rules_buf, 0, sz);
  iunlockput(ip);
  end_op();
  if(n != (int)sz)
    return -1;
  if(h->magic != RULES_MAGIC || h->nres != NRESOURCE || h->rowsize != sizeof(struct program_policy) ||
     h->nrows != RULE_MAX || h->checksum != rules_sum(rows, RULES_ROWS_BYTES))
    return -1;
  if(h->version == 1 && sz == RULES_FILE_SIZE_V1)            // the oldest file: the limits per kind keep their defaults
    return rules_import((struct program_policy*)rows) == 0 ? 1 : -1;
  if(h->version == 2 && sz == RULES_FILE_SIZE_V2){           // saved before cputime and stdout: cpu and memory only
    if(h->pad[0] != rules_sum(kb, KIND_BYTES_V2))
      return -1;
    o = (int*)kb;
    kindrules_export(cur);                                   // the current table: the two new rules keep their defaults
    for(k = 0; k < NKINDRULE; k++){
      cur[k].limit[KR_CPU] = o[4 * k];
      cur[k].limit[KR_MEM] = o[4 * k + 1];
      cur[k].action[KR_CPU] = o[4 * k + 2];
      cur[k].action[KR_MEM] = o[4 * k + 3];
    }
    if(!kindrules_sane(cur) || rules_import((struct program_policy*)rows) != 0)
      return -1;
    kindrules_import(cur);
    if(h->pad[1] == 1 || h->pad[1] == 2)
      registry_set_mode((int)h->pad[1] - 1);
    return 1;
  }
  if(h->version != RULES_VERSION || sz != RULES_FILE_SIZE ||
     h->pad[0] != rules_sum(kb, KIND_BYTES) || !kindrules_sane((struct kind_rules*)kb))
    return -1;
  if(rules_import((struct program_policy*)rows) != 0)
    return -1;
  kindrules_import((struct kind_rules*)kb);
  if(h->pad[1] == 1 || h->pad[1] == 2)
    registry_set_mode((int)h->pad[1] - 1);
  return 1;
}

// 0 = written, -1 = failed. One transaction: a power cut leaves the old file or the new one.
int
rules_save_file(void)
{
  struct inode *ip;
  struct rules_hdr *h = (struct rules_hdr*)rules_buf;
  uchar *rows = rules_buf + sizeof(struct rules_hdr);
  int n;

  memset(rules_buf, 0, sizeof(rules_buf));
  apps_rules_export((struct program_policy*)rows);       // without the rows of installed apps: their manifests set them
  kindrules_export((struct kind_rules*)(rules_buf + RULES_FILE_SIZE_V1));
  h->magic = RULES_MAGIC;
  h->version = RULES_VERSION;
  h->nres = NRESOURCE;
  h->rowsize = sizeof(struct program_policy);
  h->nrows = RULE_MAX;
  h->checksum = rules_sum(rows, RULES_ROWS_BYTES);
  h->pad[0] = rules_sum(rules_buf + RULES_FILE_SIZE_V1, KIND_BYTES);
  h->pad[1] = 1 + registry_mode();               // the registry mode is saved with the rules

  begin_op();
  ip = namei("/owner/rules");
  if(ip == 0){
    ip = create("/owner/rules", T_FILE, 0, 0);   // returned locked
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
  n = writei(ip, (char*)rules_buf, 0, RULES_FILE_SIZE);
  iunlockput(ip);
  end_op();
  return n == RULES_FILE_SIZE ? 0 : -1;
}

// Called once from owner_fs_up(), before the guard is on.
void
owner_rules_boot(void)
{
  int r = rules_load_file();

  if(r > 0)
    cprintf("[Owner] rules loaded from /owner/rules\n");
  else if(r < 0)
    cprintf("[Owner] /owner/rules is damaged: using the built-in rules\n");
  rules_snapshot();
  kindrules_snapshot();
  registry_snapshot();
}
