// Owner-Mode boot-time I/O: VGA text + COM1 out, PS/2 + COM1 in, RTC seconds.
// Polled and freestanding: usable before the kernel sets anything up. Include after types.h.
#ifndef ROOTIO_H
#define ROOTIO_H

void root_io_init(void);       // put COM1 in polled mode, detect it, clear the screen
void root_clear(void);         // clear the VGA screen, cursor to the top-left
void root_putc(int c);         // '\n' = new line, '\r' = column 0, '\b' = one column left
void root_puts(char *s);
void root_putint2(int n);      // 0..99, two characters, space padded
int  root_getkey(void);        // a key (> 0) or -1; ignores modifiers and mouse bytes
void root_drain(void);         // drop pending keyboard and serial input
int  root_rtc_seconds(void);   // RTC seconds register (raw), or -1 if it never settles
int  root_readline(char *buf, int max, int mask, int idle_secs);  // length, or -1 on idle timeout
uint root_entropy(void);       // mixes the cycle counter, the clock and key timing

#endif
