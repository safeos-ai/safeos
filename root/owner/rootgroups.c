// SafeOS process groups: the provider's table of programs (the key is the program name for now;
// a hash will replace it). A program that is not listed is an AI agent, the strictest kind.
#include "types.h"
#include "defs.h"
#include "rootowner.h"

static struct {
  char *name;
  int   kind;
} provider[] = {
  // Utilities: they run in the group of whoever starts them (System starts the Utilities group)
  { "init", PK_SYSTEM },
  { "sh", PK_TOOL }, { "ls", PK_TOOL }, { "cat", PK_TOOL },
  { "echo", PK_TOOL }, { "grep", PK_TOOL }, { "wc", PK_TOOL }, { "mkdir", PK_TOOL },
  { "rm", PK_TOOL }, { "ln", PK_TOOL }, { "kill", PK_TOOL }, { "ps", PK_TOOL },
  { "time", PK_TOOL }, { "shutdown", PK_TOOL }, { "zombie", PK_TOOL }, { "pwd", PK_TOOL }, { "safeostests", PK_TOOL }, { "rmdir", PK_TOOL }, { "touch", PK_TOOL }, { "head", PK_TOOL }, { "cp", PK_TOOL }, { "mv", PK_TOOL }, { "more", PK_TOOL },
  // the test programs
  { "usertests", PK_TOOL }, { "forktest", PK_TOOL }, { "lockstress", PK_TOOL },
  { "regtest", PK_TOOL }, { "fpuleak", PK_TOOL }, { "guardtest", PK_TOOL },
  { "killtest", PK_TOOL }, { "slowprint", PK_TOOL }, { "cpubound", PK_TOOL },
  { "preempttest", PK_TOOL }, { "stressfs", PK_TOOL },
  { "toolnap", PK_TOOL },                       // grptest under another name, for the group test
  // Apps
  { "hello", PK_APP }, { "helloagain", PK_APP },
  { "appnap", PK_APP },                         // grptest under another name, for the group test
  // AI agents (anything not listed is one too)
  { "deadloop", PK_AGENT }, { "deadloopagain", PK_AGENT },
};

int
provider_kind(char *name)
{
  int i;

  for(i = 0; i < NELEM(provider); i++)
    if(strncmp(name, provider[i].name, 16) == 0)
      return provider[i].kind;
  return registry_app_kind(name);        // an installed app: the kind its manifest declared; any other name is an Agent
}
