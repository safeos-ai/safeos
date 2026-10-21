#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"
#include "defs.h"
#include "x86.h"
#include "elf.h"
#include "fs.h"
#include "resource.h"

extern void group_exec(struct proc *p, char *name);   // proc.c
extern int registry_exec_check(struct inode *ip, char *name, char *regname);   // rootregistry.c

// Find the program to run. A name with a '/' is used as given: relative to the current directory, or absolute
// if it starts with '/'. A bare name is looked up in /bin, then in /apps/<name>/<name>. The current directory
// is not searched, so a file left in it cannot take the place of a system program: run one with ./name.
static struct inode*
find_program(char *path)
{
  char full[40];             // "/apps/" + name + "/" + name: at most 36 bytes with a 14-character name
  struct inode *ip;
  char *s;
  int n;

  for(s = path; *s; s++)
    if(*s == '/')
      return namei(path);
  n = strlen(path);
  if(n == 0 || n > DIRSIZ)
    return 0;
  memmove(full, "/bin/", 5);
  memmove(full + 5, path, n + 1);
  if((ip = namei(full)) != 0)
    return ip;
  memmove(full, "/apps/", 6);
  memmove(full + 6, path, n);
  full[6 + n] = '/';
  memmove(full + 7 + n, path, n + 1);
  return namei(full);
}


int
exec(char *path, char **argv)
{
  char *s, *last;
  char regname[16];       // the registered name of the program, if it is on the registry
  int i, off;
  uint argc, sz, sp, ustack[3+MAXARG+1];
  struct elfhdr elf;
  struct inode *ip;
  struct proghdr ph;
  pde_t *pgdir, *oldpgdir;
  struct proc *curproc = myproc();

  begin_op();

  if((ip = find_program(path)) == 0){
    end_op();
    cprintf("exec: fail\n");
    return -1;
  }
  ilock(ip);
  pgdir = 0;

  // Program identity: the hash is taken while the file is locked, so the bytes hashed are the bytes loaded.
  for(last = s = path; *s; s++)
    if(*s == '/')
      last = s+1;
  if(registry_exec_check(ip, last, regname) < 0)
    goto bad;

  // Check ELF header
  if(readi(ip, (char*)&elf, 0, sizeof(elf)) != sizeof(elf))
    goto bad;
  if(elf.magic != ELF_MAGIC)
    goto bad;

  if((pgdir = setupkvm()) == 0)
    goto bad;

  // Load program into memory.
  sz = 0;
  for(i=0, off=elf.phoff; i<elf.phnum; i++, off+=sizeof(ph)){
    if(readi(ip, (char*)&ph, off, sizeof(ph)) != sizeof(ph))
      goto bad;
    if(ph.type != ELF_PROG_LOAD)
      continue;
    if(ph.memsz < ph.filesz)
      goto bad;
    if(ph.vaddr + ph.memsz < ph.vaddr)
      goto bad;
    if((sz = allocuvm(pgdir, sz, ph.vaddr + ph.memsz)) == 0)
      goto bad;
    if(ph.vaddr % PGSIZE != 0)
      goto bad;
    if(loaduvm(pgdir, (char*)ph.vaddr, ip, ph.off, ph.filesz) < 0)
      goto bad;
  }
  iunlockput(ip);
  end_op();
  ip = 0;

  // Allocate two pages at the next page boundary.
  // Make the first inaccessible.  Use the second as the user stack.
  sz = PGROUNDUP(sz);
  if((sz = allocuvm(pgdir, sz, sz + 2*PGSIZE)) == 0)
    goto bad;
  clearpteu(pgdir, (char*)(sz - 2*PGSIZE));
  sp = sz;

  // Push argument strings, prepare rest of stack in ustack.
  for(argc = 0; argv[argc]; argc++) {
    if(argc >= MAXARG)
      goto bad;
    sp = (sp - (strlen(argv[argc]) + 1)) & ~3;
    if(copyout(pgdir, sp, argv[argc], strlen(argv[argc]) + 1) < 0)
      goto bad;
    ustack[3+argc] = sp;
  }
  ustack[3+argc] = 0;

  ustack[0] = 0xffffffff;  // fake return PC
  ustack[1] = argc;
  ustack[2] = sp - (argc+1)*4;  // argv pointer

  sp -= (3+argc+1) * 4;
  if(copyout(pgdir, sp, ustack, (3+argc+1)*4) < 0)
    goto bad;

  // Save program name for debugging.
  for(last=s=path; *s; s++)
    if(*s == '/')
      last = s+1;
  if(regname[0])
    last = regname;      // a registered program is known by its registered name, not by the name it was started under
  if(resource_admit(curproc, last) < 0)
    goto bad;

  safestrcpy(curproc->name, last, sizeof(curproc->name));
  group_exec(curproc, curproc->name);   // the process group follows the provider table

  // Commit to the user image.
  oldpgdir = curproc->pgdir;
  curproc->pgdir = pgdir;
  curproc->sz = sz;
  curproc->tf->eip = elf.entry;  // main
  curproc->tf->esp = sp;
  switchuvm(curproc);
  asm volatile("fninit");   // the new program starts with a clean x87 state
  freevm(oldpgdir);
  return 0;

 bad:
  if(pgdir)
    freevm(pgdir);
  if(ip){
    iunlockput(ip);
    end_op();
  }
  return -1;
}
