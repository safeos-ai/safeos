#include "types.h"
#include "stat.h"
#include "user.h"

int
main(void)
{
  int i;

  for(i = 1; i <= 20; i++){
    printf(1, "slowprint line %d\n", i);
    sleep(100);
  }
  exit();
}
