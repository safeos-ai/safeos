// Owner passphrase hashing, shared by the boot-time gate and, later, the live Owner session.
#include "types.h"
#include "rootblock.h"
#include "sha256.h"
#include "rootpass.h"

void
root_pass_hash(const uchar *salt, const char *pass, uint plen, uchar out[32])
{
  uchar buf[48 + ROOT_PASS_MAX];
  uint i;
  int r;

  if(plen > ROOT_PASS_MAX)
    plen = ROOT_PASS_MAX;
  // round 0: H(salt || pass)
  for(i = 0; i < 16; i++)
    buf[i] = salt[i];
  for(i = 0; i < plen; i++)
    buf[16 + i] = pass[i];
  sha256(buf, 16 + plen, out);
  // later rounds: H(previous || salt || pass)
  for(r = 1; r < ROOT_HASH_ROUNDS; r++){
    for(i = 0; i < 32; i++)
      buf[i] = out[i];
    for(i = 0; i < 16; i++)
      buf[32 + i] = salt[i];
    for(i = 0; i < plen; i++)
      buf[48 + i] = pass[i];
    sha256(buf, 48 + plen, out);
  }
  for(i = 0; i < sizeof(buf); i++)
    buf[i] = 0;
}

void
root_pass_set(struct rootblock *rb, const uchar *salt, const char *pass, uint plen)
{
  uint i;

  for(i = 0; i < 16; i++)
    rb->salt[i] = salt[i];
  root_pass_hash(salt, pass, plen, rb->hash);
  rb->passset = 1;
}

int
root_pass_verify(struct rootblock *rb, const char *pass, uint plen)
{
  uchar h[32];
  uint diff = 0, i;

  if(!rb->passset || plen > ROOT_PASS_MAX)
    return 0;
  root_pass_hash(rb->salt, pass, plen, h);
  for(i = 0; i < 32; i++)
    diff |= h[i] ^ rb->hash[i];
  return diff == 0;
}
