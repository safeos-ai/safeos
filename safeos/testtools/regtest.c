// regtest: do registers survive context switches, and does each process keep its own x87 stack?
// Three processes run the same checks at once, so the timer switches between them many times.
#include "types.h"
#include "stat.h"
#include "user.h"

#define ROUNDS 40

static int
integer_check(uint seed)           // 1 if a general register changed during the spin
{
  uint a = seed * 0x01010101 + 1, b = seed * 0x10203040 + 2, c = seed * 0x0f0f0f0f + 3,
       d = seed * 0x31415926 + 4, e = seed * 0x27182818 + 5;
  uint ra, rb, rc, rd, re;

  asm volatile(
    "movl $3000000, %%eax\n"
    "1: decl %%eax\n"
    "jnz 1b\n"
    : "=b"(ra), "=S"(rb), "=D"(rc), "=c"(rd), "=d"(re)
    : "0"(a), "1"(b), "2"(c), "3"(d), "4"(e)
    : "eax", "cc");
  return ra != a || rb != b || rc != c || rd != d || re != e;
}

static int
x87_check(uint seed)               // 1 if this process's value on the x87 stack changed
{
  int in = (int)(seed * 1000 + 7), out = 0;

  asm volatile(
    "fildl %1\n"
    "movl $3000000, %%eax\n"
    "1: decl %%eax\n"
    "jnz 1b\n"
    "fistpl %0\n"
    : "=m"(out)
    : "m"(in)
    : "eax", "cc", "st");
  return out != in;
}

int
main(void)
{
  int p[2], i, n, pid, bad_int = 0, bad_x87 = 0, msg[2];
  uint seeds[3] = {1, 2, 3};

  pipe(p);
  for(n = 0; n < 2; n++){
    pid = fork();
    if(pid < 0){
      printf(1, "regtest: fork failed\n");
      exit();
    }
    if(pid == 0){
      for(i = 0; i < ROUNDS; i++){
        bad_int += integer_check(seeds[n]);
        bad_x87 += x87_check(seeds[n]);
      }
      msg[0] = bad_int;
      msg[1] = bad_x87;
      write(p[1], msg, sizeof(msg));
      exit();
    }
  }
  for(i = 0; i < ROUNDS; i++){
    bad_int += integer_check(seeds[2]);
    bad_x87 += x87_check(seeds[2]);
  }
  for(n = 0; n < 2; n++){
    read(p[0], msg, sizeof(msg));
    bad_int += msg[0];
    bad_x87 += msg[1];
  }
  while(wait() >= 0)
    ;
  printf(1, "regtest: general registers changed %d times, x87 stack %d times (%d rounds, 3 processes)\n",
         bad_int, bad_x87, ROUNDS);
  printf(1, "regtest: %s\n", bad_int == 0 && bad_x87 == 0 ? "PASS" : "FAIL");
  exit();
}
