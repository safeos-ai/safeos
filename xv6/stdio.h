//this file is faked to look real while xv6 does not have clib,
#include "types.h"
#include "user.h"

#define fprintf(fd, fmt, ...) printf(fd, fmt, ##__VA_ARGS__)

int stdin = 0;
int stdout = 1;
int stderr = 2;