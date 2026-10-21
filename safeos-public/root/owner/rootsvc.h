#ifndef ROOTSVC_H
#define ROOTSVC_H
// The Owner's interface to the kernel. rootowner.c includes this header and no kernel
// header, so it can call only what is declared here, what resource.h declares (rule_set,
// rules_*, resource_name), the pure helpers (rootlib.h, rootblock.h, rootpass.h) and psinfo.h.
// At Ring 1 each service below becomes a gate call, and rootowner.c does not change.
// Include after types.h.

#define OWNER_PGSIZE 4096

struct psinfo;

void cprintf(char *fmt, ...);            // output (at Ring 1: formatted by the Owner, then one write call)
int  ps_snapshot(struct psinfo *out);    // snapshot of processes, CPUs, pools and rules
int  kill(int pid);
int  rules_save_file(void);              // write the live rule table to /owner/rules; 0 = ok
int  rootpool_exposure(int *total);      // how many page tables map the Owner pool
int  owner_console_getc(void);           // one key, or -1 after about one timer tick
void owner_putc(int c);                  // one output character; '\b' erases
void owner_console_busy(int v);          // 1 = ignore chords while the Owner writes files
void owner_console_close(void);          // give the keyboard and the screen back
int  owner_rtc_seconds(void);            // RTC seconds register (raw), or -1
void owner_read_block(void *dst);        // the 512-byte Owner block, sector 800
void owner_wait_request(void);           // sleep until a chord arrives
void owner_clear_requests(void);         // chords pressed during a session start no new one
extern volatile int owner_fs_ready;      // 1 once /owner and the rules file are set up
#endif
