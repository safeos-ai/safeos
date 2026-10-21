# Entry of the Ring 1 Owner. The kernel enters at address 0 at CPL 1 with the stack set.
.code32
.globl owner1_start
owner1_start:
  call owner1_main
1:
  jmp 1b
