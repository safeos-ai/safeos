// Routines to let C code use special x86 instructions.

static inline uchar
inb(ushort port)
{
  uchar data;

  asm volatile("in %1,%0" : "=a" (data) : "d" (port));
  return data;
}

static inline void
insl(int port, void *addr, int cnt)
{
  asm volatile("cld; rep insl" :
               "=D" (addr), "=c" (cnt) :
               "d" (port), "0" (addr), "1" (cnt) :
               "memory", "cc");
}

static inline void
outb(ushort port, uchar data)
{
  asm volatile("out %0,%1" : : "a" (data), "d" (port));
}

static inline void
outw(ushort port, ushort data)
{
  asm volatile("out %0,%1" : : "a" (data), "d" (port));
}

static inline void
outsl(int port, const void *addr, int cnt)
{
  asm volatile("cld; rep outsl" :
               "=S" (addr), "=c" (cnt) :
               "d" (port), "0" (addr), "1" (cnt) :
               "cc");
}

static inline void
stosb(void *addr, int data, int cnt)
{
  asm volatile("cld; rep stosb" :
               "=D" (addr), "=c" (cnt) :
               "0" (addr), "1" (cnt), "a" (data) :
               "memory", "cc");
}

static inline void
stosl(void *addr, int data, int cnt)
{
  asm volatile("cld; rep stosl" :
               "=D" (addr), "=c" (cnt) :
               "0" (addr), "1" (cnt), "a" (data) :
               "memory", "cc");
}

struct segdesc;

static inline void
lgdt(struct segdesc *p, int size)
{
  volatile ushort pd[3];

  pd[0] = size-1;
  pd[1] = (uint)p;
  pd[2] = (uint)p >> 16;

  asm volatile("lgdt (%0)" : : "r" (pd));
}

struct gatedesc;

static inline void
lidt(struct gatedesc *p, int size)
{
  volatile ushort pd[3];

  pd[0] = size-1;
  pd[1] = (uint)p;
  pd[2] = (uint)p >> 16;

  asm volatile("lidt (%0)" : : "r" (pd));
}

static inline void
ltr(ushort sel)
{
  asm volatile("ltr %0" : : "r" (sel));
}

static inline uint
readeflags(void)
{
  uint eflags;
  asm volatile("pushfl; popl %0" : "=r" (eflags));
  return eflags;
}

static inline void
loadgs(ushort v)
{
  asm volatile("movw %0, %%gs" : : "r" (v));
}

static inline void
cli(void)
{
  asm volatile("cli");
}

static inline void
sti(void)
{
  asm volatile("sti");
}

static inline uint
xchg(volatile uint *addr, uint newval)
{
  uint result;

  // The + in "+m" denotes a read-modify-write operand.
  asm volatile("lock; xchgl %0, %1" :
               "+m" (*addr), "=a" (result) :
               "1" (newval) :
               "cc");
  return result;
}

static inline uint
rcr2(void)
{
  uint val;
  asm volatile("movl %%cr2,%0" : "=r" (val));
  return val;
}

static inline void
lcr3(uint val)
{
  asm volatile("movl %0,%%cr3" : : "r" (val));
}

//PAGEBREAK: 36
// Layout of the trap frame built on the stack by the
// hardware and by trapasm.S, and passed to trap().
struct trapframe {
  // registers as pushed by pusha
  uint edi; //Maps to the %edi (Destination Index) register. Used for string/memory copying
  uint esi; //Maps to the %esi (Source Index) register. Used for string/memory copying.
  uint ebp; //Maps to the %ebp (Base Pointer) register. Tracks the user's stack frame.
  uint oesp;      // useless & ignored
  //Maps to the %esp register at the moment pushal started. True stack pointer is tracked elsewhere.
  uint ebx; //Maps to the %ebx register. A general-purpose data register.
  uint edx; //Crucial scratchpad; Maps to the %edx register. Also holds I/O port addresses.
  uint ecx; //Crucial scratchpad; Maps to the %ecx register. Used as a loop counter.
  uint eax; //Primary scratchpad (holds return values and system call numbers).Maps to the %eax register. 

  // rest of trap frame
  ushort gs; //Maps to the %gs segment register.
  ushort padding1;
  ushort fs; //Maps to the %fs segment register.
  ushort padding2;
  ushort es; //Maps to the %es (Extra Segment) data register.
  ushort padding3;
  ushort ds; //Maps to the %ds (Data Segment) selector register.
  ushort padding4;
  /*A trap is a transition between User Space → Kernel Space. The segment registers must be entirely swapped, 
  meaning the user's values must be explicitly preserved inside the trapframe to prevent data corruption upon return.
  swtch() is a transition between Kernel Thread → Kernel Thread. 
  The segment registers are already set to kernel mode values, so saving them is unnecessary.*/
  uint trapno;

  // below here defined by x86 hardware
  uint err;
  uint eip; //Maps to the %eip (Instruction Pointer / Program Counter). 
  //This is the exact address of the user instruction that was interrupted.
  ushort cs; //Maps to the %cs (Code Segment) register. This tracks the CPU privilege ring (Ring 3 for User, Ring 0 for Kernel).
  ushort padding5;
  uint eflags; //Maps to the %eflags register. Holds CPU state bits (like whether interrupts are enabled, math overflow flags, etc.).
  //A trap is a transition between User Space → Kernel Space. 
  //swtch() is a transition between Kernel Thread → Kernel Thread. 

  // below here only when crossing rings, such as from user to kernel
  uint esp; //Maps to the user program's %esp (User Stack Pointer). 
  //The kernel needs to remember exactly where the user's stack pointer was so it can restore it upon return.
  ushort ss; //Maps to the user's %ss (Stack Segment) register.
  ushort padding6;
  //A trap is a transition between User Space → Kernel Space. 
  //swtch() is a transition between Kernel Thread → Kernel Thread. 
};
