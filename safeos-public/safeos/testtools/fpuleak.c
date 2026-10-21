// fpuleak: does one process's x87 register state reach another process?
// Run at 1 CPU (./qemu.sh 1): both processes then share one FPU, so a leak shows.
#include "types.h"
#include "stat.h"
#include "user.h"

static void
dirty(void)                       // three values on the x87 register stack
{
  asm volatile("fninit; fldpi; fld1; fldz");
}

static int
tagword(void)                     // the x87 tag word: 0xffff means every register is empty
{
  uchar env[28];

  asm volatile("fnstenv %0" : "=m"(env));
  return env[8] | (env[9] << 8);
}

int
main(void)
{
  int up[2], down[2], pid, tag = 0;
  char c = 'x';

  pipe(up);                       // parent to child: "the FPU is dirty"
  pipe(down);                     // child to parent: the tag word the child saw
  pid = fork();
  if(pid < 0){
    printf(1, "fpuleak: fork failed\n");
    exit();
  }
  if(pid == 0){
    read(up[0], &c, 1);           // waits for the parent
    tag = tagword();              // the FPU state this process was given
    write(down[1], &tag, sizeof(tag));
    exit();
  }
  dirty();
  write(up[1], &c, 1);
  read(down[0], &tag, sizeof(tag));   // blocks: the child runs now
  wait();
  if(tag == 0xffff)
    printf(1, "fpuleak: no leak, the child saw an empty x87 stack\n");
  else
    printf(1, "fpuleak: LEAK, the child saw the parent's x87 registers (tag word 0x%x)\n", tag);
  exit();
}
