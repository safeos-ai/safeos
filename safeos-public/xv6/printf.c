#include "types.h"
#include "stat.h"
#include "user.h"

#define PRINTF_BUF_SIZE 512
struct printf_ctx {
  int fd;
  int idx;
  char buf[PRINTF_BUF_SIZE];
};
// Internal flush function: guarantees everything in the buffer hits the disk/screen
static void
flush_buf(struct printf_ctx *ctx)
{
  if(ctx->idx > 0){
    write(ctx->fd, ctx->buf, ctx->idx);
    ctx->idx = 0; // Reset index completely
  }
}
static void
putc_buffered(struct printf_ctx *ctx, char c)
{
  ctx->buf[ctx->idx++] = c;
  
  // Safe validation gate: flush if full or if it's a newline
  if(ctx->idx == PRINTF_BUF_SIZE || c == '\n'){
    flush_buf(ctx);
  }
}
/*static void
putc(int fd, char c)
{
  write(fd, &c, 1);
}*/
static void
printint(struct printf_ctx *ctx, int xx, int base, int sgn)
{
  static char digits[] = "0123456789ABCDEF";
  char buf[16];
  int i, neg;
  uint x;

  neg = 0;
  if(sgn && xx < 0){
    neg = 1;
    x = -xx;
  } else {
    x = xx;
  }

  i = 0;
  do{
    buf[i++] = digits[x % base];
  }while((x /= base) != 0);
  if(neg)
    buf[i++] = '-';

  while(--i >= 0)
    //putc(fd, buf[i]);
    putc_buffered(ctx, buf[i]);

}
/*static void
printint(int fd, int xx, int base, int sgn)
{
  static char digits[] = "0123456789ABCDEF";
  char buf[16];
  int i, neg;
  uint x;

  neg = 0;
  if(sgn && xx < 0){
    neg = 1;
    x = -xx;
  } else {
    x = xx;
  }

  i = 0;
  do{
    buf[i++] = digits[x % base];
  }while((x /= base) != 0);
  if(neg)
    buf[i++] = '-';

  while(--i >= 0)
    putc(fd, buf[i]);
}*/

// Print to the given fd. Only understands %d, %x, %p, %s.
void
printf(int fd, const char *fmt, ...)
{
  struct printf_ctx ctx;
  ctx.fd = fd;
  ctx.idx = 0;

  char *s;
  int c, i, state;
  uint *ap;

  state = 0;
  ap = (uint*)(void*)&fmt + 1;
  for(i = 0; fmt[i]; i++){
    c = fmt[i] & 0xff;
    if(state == 0){
      if(c == '%'){
        state = '%';
      } else {
        //putc(fd, c);
        putc_buffered(&ctx, c);
      }
    } else if(state == '%'){
      if(c == 'd'){
        //printint(fd, *ap, 10, 1);
        printint(&ctx, *ap, 10, 1);
        ap++;
      } else if(c == 'x' || c == 'p'){
        //printint(fd, *ap, 16, 0);
        printint(&ctx, *ap, 16, 0);
        ap++;
      } else if(c == 's'){
        s = (char*)*ap;
        ap++;
        if(s == 0)
          s = "(null)";
        while(*s != 0){
          //putc(fd, *s);
          putc_buffered(&ctx, *s);
          s++;
        }
      } else if(c == 'c'){
        //putc(fd, *ap);
        putc_buffered(&ctx, *ap);
        ap++;
      } else if(c == '%'){
        //putc(fd, c);
        putc_buffered(&ctx, c);
      } else {
        // Unknown % sequence.  Print it to draw attention.
        //putc(fd, '%');
        putc_buffered(&ctx, '%');
        //putc(fd, c);
        putc_buffered(&ctx, c);
      }
      state = 0;
    }
  }
  flush_buf(&ctx); 
}
