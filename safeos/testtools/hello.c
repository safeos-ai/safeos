#include "stdio.h"

int
main(void)
{
  fprintf(1, "hello (running on cpu%d)\n", getcpu());
  //fprintf(stdout, "hello\n");
  fprintf(stdout, "world\n");
  exit();
}
