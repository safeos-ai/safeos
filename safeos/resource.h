#ifndef SAFEOS_RESOURCE_H
#define SAFEOS_RESOURCE_H
// SafeOS Owner-Mode resource policy. Depends on no other header,
// so user programs can include it too (through psinfo.h).

struct proc;

#define RES_STDOUT   0
#define RES_CPUTIME  1
#define NRESOURCE    2
#define RULE_MAX     16     // rows in the rule table

#define ACTION_NONE    0x0   // count only
#define ACTION_REPORT  0x1   // report every violation
#define ACTION_KILL    0x2   // kill at violation number kill_after_index0
#define ACTION_DENY    0x4   // refuse the operation that is over the limit

#define SCOPE_PROCESS  0     // fresh budget for each process
#define SCOPE_PROGRAM  1     // one budget shared by every run of the program
#define SCOPE_GROUP    2     // an installed app's limit, counted over all the processes of its group in one launch

// Per-process counters, embedded in struct proc as p->res.
// Every process is counted, with or without a policy.
struct proc_res {
  int used[NRESOURCE];
  int violations[NRESOURCE];
  int start_tick;              // tick count when the process was created
};

// Pure configuration: what Owner-Mode decides about one program.
struct program_policy {
  char  progname[16];                 // program name; an empty name marks a free row
  int   limit[NRESOURCE];             // maximum allowed; 0 = unlimited (default)
  int   action[NRESOURCE];            // bitmask of ACTION_*
  int   kill_after_index0[NRESOURCE]; // 0 = kill on first violation, N = on (N+1)th
  int   scope[NRESOURCE];             // SCOPE_PROCESS (default) or SCOPE_PROGRAM
};

// A copy of one policy row plus its shared counters, for reports.
struct policy_view {
  char progname[16];
  int  limit[NRESOURCE];
  int  action[NRESOURCE];
  int  kill_after_index0[NRESOURCE];
  int  scope[NRESOURCE];
  int  shared_used[NRESOURCE];        // meaningful where scope is SCOPE_PROGRAM
  int  shared_violations[NRESOURCE];
};

// A rule edit request from the Ring 1 Owner: the arguments of one rule_set call (32 bytes).
struct rule_req {
  char prog[16];
  int  which;
  int  limit;
  int  action;
  int  scope;
};

// Limits per kind of group: percent of the whole machine over the recent window. One entry per kind,
// indexed by GK_* (psinfo.h). System, index 0, is never limited.
#define NKINDRULE 4
#define KR_CPU    0
#define KR_MEM    1
#define KR_CPUTIME 2          // CPU ticks of the whole group since it was launched: a count, not a percent
#define KR_STDOUT  3          // console writes of the whole group: a count, not a percent
#define KR_CPUTIME 2          // CPU ticks of the whole group since it was launched: a count, not a percent
#define KR_STDOUT  3          // console writes of the whole group: a count, not a percent
struct kind_rules {
  int limit[4];                // cpu, memory: percent of the whole machine; cputime, stdout: a count; 0 = no limit
  int action[4];               // ACTION_REPORT and/or ACTION_KILL
};
struct kind_req {              // an edit request from the Ring 1 Owner (16 bytes)
  int kind;
  int which;
  int limit;
  int action;
};
int   resource_group_check(char *name, int which, int *val, int *action, int *crossed);   // SCOPE_GROUP rows, called by app_check in proc.c
void  resource_group_launch(char *name);                           // a fresh launch of an app: the counts of its group rows start again
int   group_app_name(struct proc *p, char *buf, int n);           // proc.c: the name of p's group if it is an App or Agent group, else 0
int   kindrule_set(int kind, int which, int limit, int action);   // 0 ok, -1 bad arguments (System cannot be limited)
int   kindrule_get(int kind, int which, int *action);             // the limit in percent; 0 = none
void  kindrules_view(struct kind_rules *out);                     // copies NKINDRULE entries
void  kindrules_export(struct kind_rules *out);
int   kindrules_sane(struct kind_rules *in);                      // 1 if every entry is sane
int   kindrules_import(struct kind_rules *in);                    // replaces the table; -1 if not sane
void  kindrules_snapshot(void);
void  kindrules_restore(void);
int   kindrules_dirty(void);

// Program identity (rootregistry.c): what exec does with a program that is not on the preinstalled list.
#define REG_REPORT   0       // it runs, as an Agent, and is reported once
#define REG_ENFORCE  1       // it does not start
#define REG_DEFAULT_MODE REG_ENFORCE   // becomes REG_ENFORCE once the preinstalled list is trusted
struct reg_view {            // one registry entry, for the Owner (60 bytes)
  int  index;                // asked for by the Owner
  int  total;                // the number of preinstalled programs
  int  npre;                 // how many of them are preinstalled; the rest are installed apps
  int  kind;                 // GK_* of the entry
  char name[16];
  unsigned char hash[32];
};

// Installing (rootregistry.c, owner1.c): a staged bundle, read by the kernel for the Owner.
#define INST_MAXMANIFEST 1024
#define INST_OK          0
#define INST_BADNAME    -1      // the app name is not 1 to 14 characters without a '/'
#define INST_NOBUNDLE   -2      // no /inbox/<app>/
#define INST_NOMANIFEST -3
#define INST_NOPROGRAM  -4
#define INST_EXTRA      -5      // an entry that does not belong; its name is in extra
#define INST_TOOBIG     -6
#define INST_BUSY       -7      // the log has no room now: try again after held console output ends
#define INST_READ       -8
struct inst_view {
  char app[16];                 // in: the app name
  int  status;                  // out: INST_OK or a reason
  int  mlen;                    // out: bytes in manifest.txt
  int  plen;                    // out: bytes in the program
  char extra[16];               // out: the first unexpected entry
  int  nent;                      // out: how many entries the bundle directory holds
  char ent[8][16];              // out: the names of the first 8 of them
  unsigned char mhash[32];      // out: SHA-256 of manifest.txt
  unsigned char phash[32];      // out: SHA-256 of the program
  char manifest[INST_MAXMANIFEST + 1];   // out: the manifest text, ended by a NUL
};

// Installing, second half: the Owner sends the approved install to the kernel after the session has closed.
#define INST_C_OK       0
#define INST_C_NOFS    -1       // the file system is not ready
#define INST_C_EXISTS  -2       // already installed, or something is in the way in /apps
#define INST_C_FULL    -3       // the Owner keeps at most 8 installed apps
#define INST_C_COPY    -4       // the bundle could not be copied
#define INST_C_CHANGED -5       // the copy is not what the Owner approved: the bundle changed meanwhile
#define INST_C_RECORD  -6       // /owner/apps could not be written
#define INST_C_RULES   -7       // the rule table has no room for the app's requirements
#define INST_C_BAD     -8       // a request that does not make sense
struct inst_req {               // 200 bytes
  char app[16];
  int  status;                  // out: INST_C_OK or a reason
  int  kind;                    // GK_APP or GK_AGENT
  int  reqcpu, reqout;          // what the manifest requires: cputime and stdout per process; 0 = nothing
  char goal[80];
  char report[24];
  unsigned char mhash[32];      // the manifest as approved
  unsigned char phash[32];      // the program as approved
};

// Uninstalling: the Owner sends the approved request to the kernel after the session has closed.
#define UNINST_OK       0
#define UNINST_NOAPP   -1       // not an installed app
#define UNINST_NOFS    -2       // the file system is not ready
#define UNINST_RECORD  -3       // /owner/apps could not be written: nothing was changed
#define UNINST_FILES   -4       // removed from the record and the rules, but /apps/<app>/ stays until the next boot
#define UNINST_BAD     -5       // a request that does not make sense
struct uninst_req {             // 24 bytes
  char app[16];
  int  status;                  // out: UNINST_OK or a reason
  int  pad;
};

// Reading an app's reports (rootregistry.c, owner1.c): the Owner asks for one record at a time.
#define REP_OK       0
#define REP_NOAPP   -1           // no installed app of that name, or the position is past the last
#define REP_BUSY    -2           // the log has no room now: try again after held console output ends
#define REP_READ    -3           // a record could not be read
#define REP_RECSIZE 256          // one record: a 64-byte header written by the kernel, then 191 bytes of the app's text and a newline
#define REP_MAXREC  16           // records in a full log
struct rep_view {
  char app[16];                  // in: the app's name, used when index is negative
  int  index;                    // in: the position among the apps with a report file, or -1 to look the app up by name
  int  recno;                    // in: the record to return: 0 and up, -2 for the last one, -1 for none
  int  status;                   // out: REP_OK or a reason
  int  total;                    // out: how many apps have a report file
  char name[16];                 // out: the app
  unsigned int now;              // out: the tick now
  int  nrec;                     // out: the records in the file
  char rec[REP_RECSIZE];         // out: the record asked for. The header is the kernel's, the text is the app's and is not verified
};

// Returns -1 if the operation must be refused (a violation with ACTION_DENY), else 0.
int   resource_charge(int which, struct proc *p, int amount);
int   resource_admit(struct proc *p, char *progname);   // -1 = refuse to start
char *resource_name(int which);
char *resource_unit(int which);
int   resource_policy_view(int i, struct policy_view *out);  // -1 past the last row

// Rule editing, used by the Owner. Edits apply at once, with plain stores.
int   rule_set(char *prog, int which, int limit, int action, int scope);  // 0 ok, -1 bad arguments, -2 table full
int   rule_remove(char *prog);                       // 0 ok, -1 no such program
void  rules_export(struct program_policy *out);      // copies all RULE_MAX rows
int   rules_import(struct program_policy *in);       // replaces the table; -1 if a row is not sane
void  rules_snapshot(void);                          // remember the current table as the saved one
void  rules_restore(void);                           // go back to the remembered table
int   rules_dirty(void);                             // 1 if the table differs from the remembered one

struct program_policy;
void rules_export_except(struct program_policy *out, char (*names)[16], int n);   // rows named in names are left out
int  rules_dirty_except(char (*names)[16], int n);                                // unsaved changes, not counting those rows
void rule_remove_saved(char *prog);                                               // take a program's row out of the saved copy

#endif

// the rows of installed apps (rootregistry.c)
int  apps_rules_dirty(void);                         // unsaved program rules, not counting the rows of installed apps
struct program_policy;
void apps_rules_export(struct program_policy *out);  // the program rules as saved: without the rows of installed apps
void registry_apps_reapply(void);                    // after a revert: every installed app's rules are its manifest's again
