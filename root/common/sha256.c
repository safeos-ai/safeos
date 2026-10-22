// Freestanding SHA-256 (FIPS 180-4). No libc, no allocation.
#include "types.h"
#include "sha256.h"

#define ROTR(x, n)  (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define BSIG0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define BSIG1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SSIG0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define SSIG1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

static const uint K[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static void
sha256_block(uint h[8], const uchar *p)
{
  uint w[64], a, b, c, d, e, f, g, hh, t1, t2;
  int i;

  for(i = 0; i < 16; i++)
    w[i] = ((uint)p[4*i] << 24) | ((uint)p[4*i+1] << 16) |
           ((uint)p[4*i+2] << 8) | (uint)p[4*i+3];
  for(i = 16; i < 64; i++)
    w[i] = SSIG1(w[i-2]) + w[i-7] + SSIG0(w[i-15]) + w[i-16];

  a = h[0]; b = h[1]; c = h[2]; d = h[3];
  e = h[4]; f = h[5]; g = h[6]; hh = h[7];
  for(i = 0; i < 64; i++){
    t1 = hh + BSIG1(e) + CH(e, f, g) + K[i] + w[i];
    t2 = BSIG0(a) + MAJ(a, b, c);
    hh = g; g = f; f = e; e = d + t1;
    d = c; c = b; b = a; a = t1 + t2;
  }
  h[0] += a; h[1] += b; h[2] += c; h[3] += d;
  h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

void
sha256(const uchar *data, uint len, uchar out[32])
{
  uint h[8], n, rem, i;
  uchar blk[64];

  h[0] = 0x6a09e667; h[1] = 0xbb67ae85; h[2] = 0x3c6ef372; h[3] = 0xa54ff53a;
  h[4] = 0x510e527f; h[5] = 0x9b05688c; h[6] = 0x1f83d9ab; h[7] = 0x5be0cd19;

  for(n = 0; n + 64 <= len; n += 64)
    sha256_block(h, data + n);

  rem = len - n;
  for(i = 0; i < rem; i++)
    blk[i] = data[n + i];
  blk[rem++] = 0x80;
  if(rem > 56){
    while(rem < 64)
      blk[rem++] = 0;
    sha256_block(h, blk);
    rem = 0;
  }
  while(rem < 56)
    blk[rem++] = 0;
  // message length in bits, big-endian 64-bit (lengths here are far below 2^29 bytes)
  blk[56] = 0; blk[57] = 0; blk[58] = 0;
  blk[59] = len >> 29;
  blk[60] = len >> 21;
  blk[61] = len >> 13;
  blk[62] = len >> 5;
  blk[63] = len << 3;
  sha256_block(h, blk);

  for(i = 0; i < 8; i++){
    out[4*i]   = h[i] >> 24;
    out[4*i+1] = h[i] >> 16;
    out[4*i+2] = h[i] >> 8;
    out[4*i+3] = h[i];
  }
}
