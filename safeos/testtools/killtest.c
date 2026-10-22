#include "types.h"
#include "stat.h"
#include "user.h"

int
main(void)
{
  printf(1, "kill(2) = %d\n", kill(2));
  printf(1, "kill(9999) = %d\n", kill(9999));
  exit();
}
