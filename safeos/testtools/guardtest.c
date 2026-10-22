#include "types.h"
#include "stat.h"
#include "user.h"
#include "fcntl.h"

static int bad;

static void
expect(char *what, int r, int should_work)
{
  int works = r >= 0;

  printf(1, "%s: %s\n", what, works == should_work ? "ok" : "FAIL");
  if(works != should_work)
    bad++;
}

static int
try_open(char *path, int mode)
{
  int fd = open(path, mode);

  if(fd >= 0)
    close(fd);
  return fd;
}

int
main(void)
{
  expect("create /owner/x is refused", try_open("/owner/x", O_CREATE | O_RDWR), 0);
  expect("open /owner is refused", try_open("/owner", O_RDONLY), 0);
  expect("open owner/x (relative) is refused", try_open("owner/x", O_CREATE | O_RDWR), 0);
  expect("mkdir /owner/sub is refused", mkdir("/owner/sub"), 0);
  expect("chdir /owner is refused", chdir("/owner"), 0);
  expect("unlink /owner is refused", unlink("/owner"), 0);
  expect("link /README /owner/y is refused", link("/README", "/owner/y"), 0);
  expect("link /README /owner is refused", link("/README", "/owner"), 0);
  expect("open /README works", try_open("/README", O_RDONLY), 1);
  expect("mkdir /ownerx works", mkdir("/ownerx"), 1);
  expect("unlink /ownerx works", unlink("/ownerx"), 1);
  printf(1, "guardtest: %d failure(s)\n", bad);
  exit();
}
