#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "syscall.h"
#include "defs.h"

// Fetch the uint64 at addr from the current process.

//현재 프로세스의 주소공간에서, 특정주소 addr에 저장된
// unit64 값을 읽어오는 역할 

//addr : 읽어올 데이터주소, ip: 읽은 데이터를 저장할 포인터
int
fetchaddr(uint64 addr, uint64 *ip)
{
  //Q1: myproc()을 어떻게 쓸 수 있는가??? h만 include하는데. 
  struct proc *p = myproc();
  if(addr >= p->sz || addr+sizeof(uint64) > p->sz) // both tests needed, in case of overflow
    return -1;
  if(copyin(p->pagetable, (char *)ip, addr, sizeof(*ip)) != 0)
    return -1;
  return 0;
} //copyin -> 유저프로그램이 가지고 있는 데이터를 커널이 직접 볼 수 x, 그래서
 // 안전하게 복사해오는 기능이다. 
 /**
  * pagetable -> 어느 유저 프로세스의 메모리인가, 물리주소..? 인듯 
  * dst(ip) -> 복사받을 장소,커널메모리주소 
  * srcva(addr) -> 유저메모리에서 읽어올 시작 주소(가상주소) 
  * unit64 len -> 몇 바이트 읽을건지 
**/




// Fetch the nul-terminated string at addr from the current process.
// Returns length of string, not including nul, or -1 for error.
int
fetchstr(uint64 addr, char *buf, int max)
{
  struct proc *p = myproc();
  if(copyinstr(p->pagetable, buf, addr, max) < 0)
    return -1;
  return strlen(buf);
}

static uint64
argraw(int n)
{
  struct proc *p = myproc();
  switch (n) {
  case 0:
    return p->trapframe->a0;
  case 1:
    return p->trapframe->a1;
  case 2:
    return p->trapframe->a2;
  case 3:
    return p->trapframe->a3;
  case 4:
    return p->trapframe->a4;
  case 5:
    return p->trapframe->a5;
  }
  panic("argraw");
  return -1;
}
//trapframe -> 유저모드의 레지스터 값 저장 (trap 발생 시 유저상태 보관)
// user program -> system call || interrupt && Exception => trap! 
  // -> CPU가 점프, 커널은 유저모드상태 보존 



// Fetch the nth 32-bit system call argument.
void
argint(int n, int *ip)
{
  *ip = argraw(n);
}

// Retrieve an argument as a pointer.
// Doesn't check for legality, since
// copyin/copyout will do that.
void
argaddr(int n, uint64 *ip)
{
  *ip = argraw(n);
}

// Fetch the nth word-sized system call argument as a null-terminated string.
// Copies into buf, at most max.
// Returns string length if OK (including nul), -1 if error.
int
argstr(int n, char *buf, int max)
{
  uint64 addr;
  argaddr(n, &addr);
  return fetchstr(addr, buf, max);
}

// Prototypes for the functions that handle system calls.
extern uint64 sys_fork(void);
extern uint64 sys_exit(void);
extern uint64 sys_wait(void);
extern uint64 sys_pipe(void);
extern uint64 sys_read(void);
extern uint64 sys_kill(void);
extern uint64 sys_exec(void);
extern uint64 sys_fstat(void);
extern uint64 sys_chdir(void);
extern uint64 sys_dup(void);
extern uint64 sys_getpid(void);
extern uint64 sys_sbrk(void);
extern uint64 sys_sleep(void);
extern uint64 sys_uptime(void);
extern uint64 sys_open(void);
extern uint64 sys_write(void);
extern uint64 sys_mknod(void);
extern uint64 sys_unlink(void);
extern uint64 sys_link(void);
extern uint64 sys_mkdir(void);
extern uint64 sys_close(void);

//PA1
extern uint64 sys_getnice(void);
extern uint64 sys_setnice(void);
extern uint64 sys_ps(void);
extern uint64 sys_meminfo(void);
extern uint64 sys_waitpid(void);

extern int sys_mmap(void);
extern int sys_munmap(void);
extern int sys_freemem(void);

// An array mapping syscall numbers from syscall.h
// to the function that handles the system call.
static uint64 (*syscalls[])(void) = {
[SYS_fork]    sys_fork, //sysproc.c에 구현되어있다. 
[SYS_exit]    sys_exit,
[SYS_wait]    sys_wait,
[SYS_pipe]    sys_pipe,
[SYS_read]    sys_read,
[SYS_kill]    sys_kill,
[SYS_exec]    sys_exec,
[SYS_fstat]   sys_fstat,
[SYS_chdir]   sys_chdir,
[SYS_dup]     sys_dup,
[SYS_getpid]  sys_getpid,
[SYS_sbrk]    sys_sbrk,
[SYS_sleep]   sys_sleep,
[SYS_uptime]  sys_uptime,
[SYS_open]    sys_open,
[SYS_write]   sys_write,
[SYS_mknod]   sys_mknod,
[SYS_unlink]  sys_unlink,
[SYS_link]    sys_link,
[SYS_mkdir]   sys_mkdir,
[SYS_close]   sys_close,

//PA1
[SYS_getnice] sys_getnice,
[SYS_setnice] sys_setnice,
[SYS_ps] sys_ps,
[SYS_meminfo] sys_meminfo,
[SYS_waitpid] sys_waitpid,

[SYS_mmap] sys_mmap,
[SYS_munmap] sys_munmap,
[SYS_freemem] sys_freemem
};

void
syscall(void)
{
  int num;
  struct proc *p = myproc();

  num = p->trapframe->a7; //system call의 번호 
  if(num > 0 && num < NELEM(syscalls) && syscalls[num]) {
    // Use num to lookup the system call function for num, call it,
    // and store its return value in p->trapframe->a0
    p->trapframe->a0 = syscalls[num]();
  } else {
    printf("%d %s: unknown sys call %d\n",
            p->pid, p->name, num);
    p->trapframe->a0 = -1;
  }
}
