# Trampoline entry. Runs at physical 0x7000, called from the Owner-Mode gate with
# paging on (low 4 MB identity-mapped). Turns paging off, then loads the next kernel.
.code32
.globl start
start:
  cli
  cld
  movl $0x7000, %esp
  movl %cr0, %eax
  andl $0x7FFEFFFF, %eax      # clear CR0.PG (bit 31) and CR0.WP (bit 16)
  movl %eax, %cr0
  call chainmain
spin:
  jmp spin
