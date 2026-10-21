#include "types.h"
#include "stat.h"
#include "user.h"

int
main(void)
{
  printf(1, "shutting down...\n");
  shutdown();
  exit();  // only reached if shutdown fails
}
