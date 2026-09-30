#include "stdio.h"

int
main(void)
{
  for (int i=0; ; i++) {
    fprintf(stdout, "i=%d\n", i);
  }
  exit();
}
