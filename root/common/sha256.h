#ifndef SHA256_H
#define SHA256_H
// Freestanding SHA-256. Include after types.h.
void sha256(const uchar *data, uint len, uchar out[32]);
#endif
