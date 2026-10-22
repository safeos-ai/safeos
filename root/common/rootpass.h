#ifndef ROOTPASS_H
#define ROOTPASS_H
// Owner passphrase: salted, iterated SHA-256. Include after types.h and rootblock.h.
#define ROOT_PASS_MAX    64
#define ROOT_HASH_ROUNDS 2000

void root_pass_hash(const uchar *salt, const char *pass, uint plen, uchar out[32]);
void root_pass_set(struct rootblock *rb, const uchar *salt, const char *pass, uint plen);
int  root_pass_verify(struct rootblock *rb, const char *pass, uint plen);   // 1 = match
#endif
