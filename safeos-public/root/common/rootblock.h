// Owner-Mode persistent state: one 512-byte sector in xv6.img (drive 0).
// Shared by the boot-time gate (polled I/O, before any OS exists) and by the
// running SafeOS kernel (buffer cache). Static layout only: no allocator needed.
// Include after types.h.
#ifndef ROOTBLOCK_H
#define ROOTBLOCK_H

#define ROOT_SECTOR   800          // must stay below FSSIZE: kernels reach it as bread(0, ROOT_SECTOR)
#define ROOT_MAGIC    0x52543031
#define ROOT_VERSION  2

#define ROOT_KERNEL_XV6     0
#define ROOT_KERNEL_SAFEOS  1

#define ROOT_STAGE_NONE      0   // no hand-over pending
#define ROOT_STAGE_HANDOVER  1   // the gate started the second kernel; nobody has confirmed
//                       2   reserved: the second kernel is in early boot (not used yet)
#define ROOT_STAGE_CONFIRMED 3   // the second kernel reached its first process with a working file system

#define ROOTBLOCK_OK        0
#define ROOTBLOCK_BLANK     1      // magic missing: never written
#define ROOTBLOCK_DAMAGED   2      // magic present, but version or checksum wrong

struct rootblock {
  uint magic;
  uint version;
  uint chosen;       // kernel that boots by default
  uint stage;        // boot stage of the last hand-over (ROOT_STAGE_*)
  uint failures;     // failed trials seen
  uint checksum;     // over every other word: detects damage, not tampering
  uint passset;      // 1 once an Owner passphrase has been set
  uchar salt[16];    // random salt for the passphrase hash
  uchar hash[32];    // iterated SHA-256 of salt + passphrase
  uchar pad[436];
};

typedef char rootblock_size_check[(sizeof(struct rootblock) == 512) ? 1 : -1];

static inline uint
rootblock_sum(struct rootblock *rb)
{
  uint *w = (uint*)rb;
  uint s = 0x12345678;
  int i;

  for(i = 0; i < 128; i++){
    if(&w[i] == (uint*)&rb->checksum)
      continue;
    s = ((s << 7) | (s >> 25)) ^ w[i];
  }
  return s;
}

static inline void
rootblock_seal(struct rootblock *rb)
{
  rb->checksum = rootblock_sum(rb);
}

static inline int
rootblock_check(struct rootblock *rb)
{
  if(rb->magic != ROOT_MAGIC)
    return ROOTBLOCK_BLANK;
  if(rb->version != ROOT_VERSION || rb->checksum != rootblock_sum(rb))
    return ROOTBLOCK_DAMAGED;
  return ROOTBLOCK_OK;
}

static inline void
rootblock_init(struct rootblock *rb, uint chosen)
{
  uchar *p = (uchar*)rb;
  int i;

  for(i = 0; i < 512; i++)
    p[i] = 0;
  rb->magic = ROOT_MAGIC;
  rb->version = ROOT_VERSION;
  rb->chosen = chosen;
  rootblock_seal(rb);
}

#endif
