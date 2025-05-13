#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"

#include "file.h"


struct cpu cpus[NCPU]; // muti-core 

struct proc proc[NPROC]; //array of process

struct proc *initproc; //first process 

int nextpid = 1; //새로운 프로세스를 생성할 때 사용할 다음 PID값 
struct spinlock pid_lock; // nextpid 접근 시 사용하는 스핀락 


static int niceWeight[40] = {
  88761, 71755, 56483, 46273, 36291, 29154, 23254, 18705,
  14949, 11916, 9548, 7620, 6100, 4904, 3906, 3121,
  2501, 1991, 1586, 1277, 1024, 820, 655, 526,
  423, 335, 272, 215, 172, 137, 110, 87,
  70, 56, 45, 36, 29, 23, 18, 15
}; //0~39


#define MMAPBASE 0x40000000

struct mmap_area ma[64] = {0};



//자식 프로세스를 유저모드로 보내주는 함수 
//fork -> 자식프로세스 / 스케쥴러가 선택시 실행 시작 -> 커널 스택의 복귀지점 
extern void forkret(void); 
static void freeproc(struct proc *p); //프로세스의 메모리 해제 

// user -> kernel 전환시 실행되는 코드, trampoline.S에 있으며 트랩시 실행 
extern char trampoline[]; // trampoline.S
//역할은 → 유저 모드로 "점프"하거나, 커널로 "복귀"하는 과정 처리

// helps ensure that wakeups of wait()ing
// parents are not lost. helps obey the
// memory model when using p->parent.
// must be acquired before any p->lock.
struct spinlock wait_lock; //wait() 동안 동기화를 위해 사용 
 
// Allocate a page for each process's kernel stack.
// Map it high in memory, followed by an invalid
// guard page.
void
proc_mapstacks(pagetable_t kpgtbl)
{
  struct proc *p;
  
  for(p = proc; p < &proc[NPROC]; p++) {
    char *pa = kalloc();
    if(pa == 0)
      panic("kalloc");
    uint64 va = KSTACK((int) (p - proc));
    kvmmap(kpgtbl, va, (uint64)pa, PGSIZE, PTE_R | PTE_W);
  }
}


//최초에 한번 하기 때문에 allocproc ㄱㄱ 
// initialize the proc table. 
void
procinit(void)
{
  struct proc *p;
  
  initlock(&pid_lock, "nextpid");
  initlock(&wait_lock, "wait_lock");
  for(p = proc; p < &proc[NPROC]; p++) {
      initlock(&p->lock, "proc");
      p->state = UNUSED;
      p->kstack = KSTACK((int) (p - proc));
      p->nice = 20;
  }
}

// Must be called with interrupts disabled,
// to prevent race with process being moved
// to a different CPU.
int
cpuid()
{
  int id = r_tp(); // tp레지스터값 반환 (Thread Pointer, 동작중인 CPUd의 core num을 저장 )
  return id;
}

// Return this CPU's cpu struct.
// Interrupts must be disabled.
struct cpu*
mycpu(void)
{
  int id = cpuid();
  struct cpu *c = &cpus[id];
  return c;
}

//현재프로세스의 정보를 얻는 것 
// Return the current struct proc *, or zero if none.
struct proc*
myproc(void)
{
  push_off(); //인터럽트 비활성화  -> "중단된" 상태에서 안전하게 값을 조회하도록 하기 위해!
  struct cpu *c = mycpu(); //현재 CPU 정보 얻고 
  struct proc *p = c->proc; //현재 CPU에서 실행 중인 프로세스 찾고 
  pop_off(); //인터럽트 원래 상태로 복구 
  return p; //프로세스 정보 반환 
}

int
allocpid()
{
  int pid;
  
  acquire(&pid_lock);
  pid = nextpid;
  nextpid = nextpid + 1;
  release(&pid_lock);

  return pid;
}


// Look in the process table for an UNUSED proc.
// If found, initialize state required to run in the kernel,
// and return with p->lock held.
// If there are no free procs, or a memory allocation fails, return 0.
static struct proc*
allocproc(void)
{
  struct proc *p;

  for(p = proc; p < &proc[NPROC]; p++) {
    acquire(&p->lock);
    if(p->state == UNUSED) {
      goto found;
    } else {
      release(&p->lock);
    }
  }
  return 0;

found:
  p->pid = allocpid();
  p->state = USED;
  
  //PA2
  p->timeslice= 5;
  p->eligible = 1;
  p->nice = 20;
  p->weight = niceWeight[p->nice];
  p->runtime = 0;
  p->vruntime = 0;
  p->vdeadline = p->vruntime + (p->timeslice * 1024/p->weight);
  
  
  


  // Allocate a trapframe page.
  if((p->trapframe = (struct trapframe *)kalloc()) == 0){
    freeproc(p);
    release(&p->lock);
    return 0;
  }

  // An empty user page table.
  p->pagetable = proc_pagetable(p);
  if(p->pagetable == 0){
    freeproc(p);
    release(&p->lock);
    return 0;
  }

  // Set up new context to start executing at forkret,
  // which returns to user space.
  memset(&p->context, 0, sizeof(p->context)); //context 초기화 (schedular()가 프로세스 실행 시 참고하는 레지스터들이다.)
  p->context.ra = (uint64)forkret;
  p->context.sp = p->kstack + PGSIZE;

  return p;
}


// free a proc structure and the data hanging from it,
// including user pages.
// p->lock must be held.
static void
freeproc(struct proc *p)
{
  if(p->trapframe)
    kfree((void*)p->trapframe);
  p->trapframe = 0;
  if(p->pagetable)
    proc_freepagetable(p->pagetable, p->sz);
  p->pagetable = 0;
  p->sz = 0;
  p->pid = 0;
  p->parent = 0;
  p->name[0] = 0;
  p->chan = 0;
  p->killed = 0;
  p->xstate = 0;
  p->state = UNUSED;
}

// Create a user page table for a given process, with no user memory,
// but with trampoline and trapframe pages.
pagetable_t
proc_pagetable(struct proc *p)
{
  pagetable_t pagetable;

  // An empty page table.
  pagetable = uvmcreate();
  if(pagetable == 0)
    return 0;

  // map the trampoline code (for system call return)
  // at the highest user virtual address.
  // only the supervisor uses it, on the way
  // to/from user space, so not PTE_U.
  if(mappages(pagetable, TRAMPOLINE, PGSIZE,
              (uint64)trampoline, PTE_R | PTE_X) < 0){
    uvmfree(pagetable, 0);
    return 0; 
  } //trampoline의 역할 -> 커널에서 제공, 유저모드<->커널모드 전환코드임
// system call -> trampoline으로 가서 trampframe(register 저장소)에 user mode 데이터 저장
// TRAMPOLINE -> MAXVA-PGSIZE, userpage의 가상 끝주소..(가장 위에있는 공간 ) 


  // map the trapframe page just below the trampoline page, for
  // trampoline.S.
  if(mappages(pagetable, TRAPFRAME, PGSIZE,
              (uint64)(p->trapframe), PTE_R | PTE_W) < 0){
    uvmunmap(pagetable, TRAMPOLINE, 1, 0);
    uvmfree(pagetable, 0);
    return 0;
  }

  return pagetable;
}


//page table -> 가상주소를 물리주소를 매핑해준다
// systemcall-> trap-> page table을 참고해 trampoline을 실행(????)-> 커널이 사용자레지스터 값을 trapframe에 저장 -> trampoline을 통해 다시 usermode로 변환 

// Free a process's page table, and free the
// physical memory it refers to.
void
proc_freepagetable(pagetable_t pagetable, uint64 sz)
{
  uvmunmap(pagetable, TRAMPOLINE, 1, 0);
  uvmunmap(pagetable, TRAPFRAME, 1, 0);
  uvmfree(pagetable, sz);
}

// a user program that calls exec("/init")
// assembled from ../user/initcode.S
// od -t xC ../user/initcode
uchar initcode[] = {
  0x17, 0x05, 0x00, 0x00, 0x13, 0x05, 0x45, 0x02,
  0x97, 0x05, 0x00, 0x00, 0x93, 0x85, 0x35, 0x02,
  0x93, 0x08, 0x70, 0x00, 0x73, 0x00, 0x00, 0x00,
  0x93, 0x08, 0x20, 0x00, 0x73, 0x00, 0x00, 0x00,
  0xef, 0xf0, 0x9f, 0xff, 0x2f, 0x69, 0x6e, 0x69,
  0x74, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00
};

// Set up first user process.
void
userinit(void)
{
  struct proc *p;

  p = allocproc();
  initproc = p;
  
  // allocate one user page and copy initcode's instructions
  // and data into it.
  uvmfirst(p->pagetable, initcode, sizeof(initcode));
  p->sz = PGSIZE;

  // prepare for the very first "return" from kernel to user.
  p->trapframe->epc = 0;      // user program counter
  p->trapframe->sp = PGSIZE;  // user stack pointer

  safestrcpy(p->name, "initcode", sizeof(p->name));
  p->cwd = namei("/");

  p->state = RUNNABLE;

  release(&p->lock);
}

// Grow or shrink user memory by n bytes.
// Return 0 on success, -1 on failure.
int
growproc(int n)
{
  uint64 sz;
  struct proc *p = myproc();

  sz = p->sz;
  if(n > 0){
    if((sz = uvmalloc(p->pagetable, sz, sz + n, PTE_W)) == 0) {
      return -1;
    }
  } else if(n < 0){
    sz = uvmdealloc(p->pagetable, sz, sz + n);
  }
  p->sz = sz;
  return 0;
}

// Create a new process, copying the parent.
// Sets up child kernel stack to return as if from fork() system call.
int
fork(void)
{
  int i, pid;
  struct proc *np;
  struct proc *p = myproc();

 // printf("DEBUG: Fork called by proc[%d]\n", p->pid);
  // Allocate process.
  if((np = allocproc()) == 0){
    //printf("DEBUG: Fork failed: allocproc returned 0\n");
    return -1; //fail 
  }


  //부모의 페이지테이블을 자식에게 복사. uvmcopy -> 가상메모리공간을 자식에게 복사 
  // Copy user memory from parent to child.
  if(uvmcopy(p->pagetable, np->pagetable, p->sz) < 0){//부모의 주소공간에서 자식의 주소공간으로 p->sz바이트만큼 메모리 복사 
    freeproc(np);
    release(&np->lock);
    //printf("DEBUG: Fork failed: uvmcopy error\n");
    return -1; //fail 
  }
  np->sz = p->sz;
  
  // copy saved user registers.
  *(np->trapframe) = *(p->trapframe);

  // Cause fork to return 0 in the child.
  np->trapframe->a0 = 0;

  // increment reference counts on open file descriptors.
  for(i = 0; i < NOFILE; i++)
    if(p->ofile[i])
      np->ofile[i] = filedup(p->ofile[i]);

  np->cwd = idup(p->cwd); 
  safestrcpy(np->name, p->name, sizeof(p->name));
  for (int i = 0; i<64; i++){
    if ((ma[i].addr == 0) && (ma[i].p == p)){
      for(int j = 0;j<64;j++){
        if (ma[j].addr == 0){
          ma[j].f = ma[i].f;
          ma[j].addr = ma[i].addr;
          ma[j].length = ma[i].length;
          ma[j].offset = ma[i].offset;
          ma[j].prot = ma[i].prot;
          ma[j].flags = ma[i].flags;
          ma[j].p = np;

          uint va = 0;
          uint addr = ma[i].addr;
          pte_t* pte;
          int prot_write = 0;

          char* mem = 0;
          
          for(va = addr; va < addr+ma[i].length; va += PGSIZE){
            pte = walk(p->pagetable, (uint64)(va), 0);
            if(!pte) continue; // not in pte pass
            if(!(*pte & PTE_V)) continue;
            mem = kalloc();
            if(!mem) return 0;
            memset(mem, 0, PGSIZE);
            memmove(mem, (char*)va, PGSIZE);
            int prots = ma[i].prot | PTE_U;
            if (prot_write) prots = prots | PTE_W;
            if (mappages(np->pagetable, (uint64)va, PGSIZE, (uint64)(mem), prots) == -1) return 0;
          }
          break;
        }
      }
    }
  }
  pid = np->pid;

  np->nice = p->nice;
  np->vruntime = p->vruntime;
  np->weight = p->weight;
  np->runtime = 0;
  np->timeslice = 5;
  np->vdeadline = np->vruntime + (5 * 1024 / np->weight);
  //printf("DEBUG: Fork: Child proc[%d] created: vruntime=%lu, vdeadline=%lu, nice=%d, weight=%lu\n",
    //np->pid, np->vruntime, np->vdeadline, np->nice, np->weight);

  release(&np->lock);

  acquire(&wait_lock);
  np->parent = p;
  release(&wait_lock);


  acquire(&proc->lock);
  np->state = RUNNABLE;
  release(&proc->lock);

  return pid;
}

// Pass p's abandoned children to init.
// Caller must hold wait_lock.
//부모 프로세스 p가 죽었을 때, 자식프로세스의 부모를 init으로. 
void
reparent(struct proc *p)
{
  struct proc *pp;

  for(pp = proc; pp < &proc[NPROC]; pp++){
    if(pp->parent == p){
      pp->parent = initproc;
      wakeup(initproc);
    }
  }
}

// Exit the current process.  Does not return.
// An exited process remains in the zombie state
// until its parent calls wait().
void
exit(int status)
{
  struct proc *p = myproc();

  if(p == initproc)
    panic("init exiting");

  // Close all open files.
  for(int fd = 0; fd < NOFILE; fd++){
    if(p->ofile[fd]){
      struct file *f = p->ofile[fd];
      fileclose(f);
      p->ofile[fd] = 0;
    }
  }

  begin_op();
  iput(p->cwd);
  end_op();
  p->cwd = 0;

  acquire(&wait_lock);

  // Give any children to init.
  reparent(p);

  // Parent might be sleeping in wait().
  wakeup(p->parent); //sleeping 을 runnable로 바꿔 
  
  acquire(&p->lock);

  p->xstate = status; //종료상태 저장 
  p->state = ZOMBIE; 

  release(&wait_lock);

  // Jump into the scheduler, never to return.
  sched(); //스케줄러에게 CPU양도 
  panic("zombie exit");
}

// Wait for a child process to exit and return its pid.
// Return -1 if this process has no children.
int
wait(uint64 addr) //코드를 보면 알듯이 하나만 처리해준다? 둘이면 우짬 
{
  struct proc *pp;
  int havekids, pid;
  struct proc *p = myproc();

  acquire(&wait_lock);

  for(;;){
    // Scan through table looking for exited children.
    havekids = 0;
    for(pp = proc; pp < &proc[NPROC]; pp++){
      if(pp->parent == p){
        // make sure the child isn't still in exit() or swtch().
        acquire(&pp->lock);

        havekids = 1;
        if(pp->state == ZOMBIE){
          // Found one.
          pid = pp->pid;
          if(addr != 0 && copyout(p->pagetable, addr, (char *)&pp->xstate,
                                  sizeof(pp->xstate)) < 0) {
            release(&pp->lock);
            release(&wait_lock);
            return -1;
          }
          freeproc(pp);
          release(&pp->lock);
          release(&wait_lock);
          return pid;
        }
        release(&pp->lock);
      }
    }

    // No point waiting if we don't have any children.
    if(!havekids || killed(p)){
      release(&wait_lock);
      return -1;
    }
    
    // Wait for a child to exit.
    sleep(p, &wait_lock);  //DOC: wait-sleep
  }
}

// Per-CPU process scheduler.
// Each CPU calls scheduler() after setting itself up.
// Scheduler never returns.  It loops, doing:
//  - choose a process to run.
//  - swtch to start running that process.
//  - eventually that process transfers control
//    via swtch back to the scheduler.
void
scheduler(void)
{
	struct proc *p=0,*priority=0;
  struct cpu *c = mycpu(); //이 CPU에서 현재돌고 있는 프로세스)

  c->proc = 0;//가 없음
  printf("DEBUG: Scheduler started on CPU \n");

  for(;;){
    // The most recent process to run may have had interrupts
    // turned off; enable them to avoid a deadlock if all
    // processes are waiting.
    intr_on();

    acquire(&proc.lock);
    int first=1;   
    for(p = proc; p < &proc[NPROC]; p++) {
      
      if(p->state == RUNNABLE && p->eligible) {
        if (first) {
          priority = p;
          first = 0;
          continue;
        }
        if (p->vdeadline < priority->vdeadline){
          priority = p;
        }
        // Switch to chosen process.  It is the process's job
        // to release its lock and then reacquire it
        // before jumping back to us.
      }
    }
    if (first){ //대기모드로 들어감
      //printf("DEBUG: No process is RUNNABLE && eligible. CPU idling.\n");
      // nothing to run; stop running on this core until an interrupt.
      intr_on(); 
      asm volatile("wfi");
      continue;
    }
    p = priority;
    p->state = RUNNING;
    c->proc = p;
    //printf("DEBUG: Scheduler selected proc[%d] with vdeadline=%lu\n", p->pid, p->vdeadline);
    swtch(&c->context, &p->context);
    //printf("DEBUG: Proc[%d] yielded back to scheduler\n", p->pid);
    c->proc = 0;
    release(&proc->lock);
  }
}


// Switch to scheduler.  Must hold only p->lock
// and have changed proc->state. Saves and restores
// intena because intena is a property of this
// kernel thread, not this CPU. It should
// be proc->intena and proc->noff, but that would
// break in the few places where a lock is held but
// there's no process.
void
sched(void) //프로세스 A 실행 끝났으니,이제 스케줄러로 돌아갈래! 라는 함ㅅ ㅜ
{
  int intena;
  struct proc *p = myproc();

  if(!holding(&p->lock))
    panic("sched p->lock");
  if(mycpu()->noff != 1)
    panic("sched locks");
  if(p->state == RUNNING)
    panic("sched running");
  if(intr_get())
    panic("sched interruptible");

  intena = mycpu()->intena; //인터럽트 상태..저장 뭔소리야 
  swtch(&p->context, &mycpu()->context); //나-> 스케줄러(mycpu)로 context전환 
  mycpu()->intena = intena; // 인터럽트 상태 복원 
}

// Give up the CPU for one scheduling round.
void
yield(void)
{
  struct proc *p = myproc();
 // printf("DEBUG: Proc[%d] yielding: state=%d, vruntime=%lu, vdeadline=%lu\n",
   // p->pid, p->state, p->vruntime, p->vdeadline);
  acquire(&p->lock);
  p->state = RUNNABLE;
  sched();
 //printf("DEBUG: Proc[%d] resumed after yield\n", p->pid);

  release(&p->lock);

}

// A fork child's very first scheduling by scheduler()
// will swtch to forkret.
void
forkret(void)
{
  static int first = 1;

  // Still holding p->lock from scheduler.
  release(&myproc()->lock);

  if (first) {
    // File system initialization must be run in the context of a
    // regular process (e.g., because it calls sleep), and thus cannot
    // be run from main().
    fsinit(ROOTDEV);

    first = 0;
    // ensure other cores see first=0. 
    __sync_synchronize();
  }

  usertrapret();
  //fort는 user mode로 복귀하면서, trapframe의 PC(program counter)가 fork이후의 코드를
  //실행하는 것이다. 
}

// Atomically release lock and sleep on chan.
// Reacquires lock when awakened.
void
sleep(void *chan, struct spinlock *lk)
{
  struct proc *p = myproc();
  
  // Must acquire p->lock in order to
  // change p->state and then call sched.
  // Once we hold p->lock, we can be
  // guaranteed that we won't miss any wakeup
  // (wakeup locks p->lock),
  // so it's okay to release lk.

  acquire(&p->lock);  //DOC: sleeplock1
  release(lk);

/**
 * 
 * sleep해도 정보 유지 
 * non-eligible -> 스케쥴링 대상 아님 
 * wakeup후에 재계산하므로, 손댈필요없음 
 */

  // Go to sleep.
  p->chan = chan; //reason of sleeping
  p->state = SLEEPING;

  sched();

  // Tidy up.
  p->chan = 0;

  // Reacquire original lock.
  release(&p->lock);
  acquire(lk);
}

// Wake up all processes sleeping on chan.
// Must be called without any p->lock.
void
wakeup(void *chan)
{
  struct proc *p;
  for(p = proc; p < &proc[NPROC]; p++) {
    if(p != myproc()){
      p->timeslice=5; //이제 다시 시작
      p->vdeadline = p->vruntime + (5 * 1024 / p->weight);
  
      if(p->state == SLEEPING && p->chan == chan) {
        p->state = RUNNABLE;
      }
    }
  }
}

// Kill the process with the given pid.
// The victim won't exit until it tries to return
// to user space (see usertrap() in trap.c).
int
kill(int pid)
{
  struct proc *p;

  for(p = proc; p < &proc[NPROC]; p++){
    acquire(&p->lock);
    if(p->pid == pid){
      p->killed = 1;
      if(p->state == SLEEPING){
        // Wake process from sleep().
        p->state = RUNNABLE;
      }
      release(&p->lock);
      return 0;
    }
    release(&p->lock);
  }
  return -1;
}

void
setkilled(struct proc *p)
{
  acquire(&p->lock);
  p->killed = 1;
  release(&p->lock);
}

int
killed(struct proc *p)
{
  int k;
  
  acquire(&p->lock);
  k = p->killed;
  release(&p->lock);
  return k;
}

// Copy to either a user address, or kernel address,
// depending on usr_dst.
// Returns 0 on success, -1 on error.
int
either_copyout(int user_dst, uint64 dst, void *src, uint64 len)
{
  struct proc *p = myproc();
  if(user_dst){
    return copyout(p->pagetable, dst, src, len);
  } else {
    memmove((char *)dst, src, len);
    return 0;
  }
}//커널이 데이터를 유저에게 전달할 때 ??? 

// Copy from either a user address, or kernel address,
// depending on usr_src.
// Returns 0 on success, -1 on error.
int
either_copyin(void *dst, int user_src, uint64 src, uint64 len)
{
  struct proc *p = myproc();
  if(user_src){
    return copyin(p->pagetable, dst, src, len);
  } else {
    memmove(dst, (char*)src, len);
    return 0;
  }
}//시스템콜에서 유저가 보낸 데이터 받아올 때 

// Print a process listing to console.  For debugging.
// Runs when user types ^P on console.
// No lock to avoid wedging a stuck machine further.
void
procdump(void)
{
  static char *states[] = {
  [UNUSED]    "unused",
  [USED]      "used",
  [SLEEPING]  "sleep ",
  [RUNNABLE]  "runble",
  [RUNNING]   "run   ",
  [ZOMBIE]    "zombie"
  };


  struct proc *p;
  char *state;

  printf("\n");
  for(p = proc; p < &proc[NPROC]; p++){
    if(p->state == UNUSED)
      continue;
    if(p->state >= 0 && p->state < NELEM(states) && states[p->state])
      state = states[p->state];
    else
      state = "???";
    printf("%d %s %s", p->pid, state, p->name);
    printf("\n");
  }
}//디버깅용?? 함수. 모든 프로세스의 상태를 출력한댄다 


//PA1
int
getnice(int pid) 
{
  struct proc *p;
  for( p = proc; p< &proc[NPROC];p++){
    if(p->pid == pid){
      return p->nice;
    }
  }
  return -1;
}

int
setnice(int pid, int value)
{
  if (value< 0 || value >39){
    return -1;
  }

  struct proc *p;
  for( p = proc; p< &proc[NPROC];p++){
    if (p->pid == pid){
      p->nice = value;
      p->weight = niceWeight[p->nice];
      return 0;
    }
  }
  return -1;
}


void 
ps(int pid)
{
  struct proc *p;
  int first = 1;
  static char* states[] = {
  	[UNUSED] = "UNUSED",
       	[USED] = "USED",
       	[SLEEPING] = "SLEEPING",
  	[RUNNABLE] = "RUNNABLE",
       	[RUNNING] = "RUNNING", 
	[ZOMBIE] = "ZOMBIE"
	};
	
  if (pid ==0){//전체
    printf("name     pid  state    priority  runtime/weight  runtime  vruntime  vdeadline  is_eligible  tick\n");
    for(p=proc;p<&proc[NPROC];p++){
      if (p->state != UNUSED){
        char *eligible = (p->eligible == 1) ? "true" : "false";

        //millitick 
        printf("%-8s %-4d %-8s %-9d %-15lu %-8lu %-9lu %-10lu %-12s %u\n",
          p->name,
          p->pid,
          states[p->state],
          p->nice,
          (p->weight == 0) ? 0 : (p->runtime * 1000 / p->weight),
          p->runtime * 1000,
          p->vruntime,
          p->vdeadline,
          eligible,
          ticks * 1000
        );
      }
    }  
  }
  else {//pid 하나만 
    for (p=proc;p<&proc[NPROC];p++){
      if (first){
        printf("name     pid  state    priority  runtime/weight  runtime  vruntime  vdeadline  is_eligible  tick\n");
        first = 0;
      }
      if (pid == p->pid && p->state != UNUSED){
        char *eligible = (p->eligible == 1) ? "true" : "false";

        printf("%-8s %-4d %-8s %-9d %-15lu %-8lu %-9lu %-10lu %-12s %u\n",
          p->name,
          p->pid,
          states[p->state],
          p->nice,
          (p->weight == 0) ? 0 : (p->runtime * 1000 / p->weight),
          p->runtime * 1000,
          p->vruntime,
          p->vdeadline,
          eligible,
          ticks * 1000
        );
        
      }
    }
  }
}
  


int
meminfo(void)
{ 
  struct proc *p;
  int free_mem= PHYSTOP - KERNBASE; 
  
  for(p = proc; p < &proc[NPROC]; p++){
    if(p->state != UNUSED) {
      free_mem -= p->sz;
      }
    }
  return free_mem;
} 


//suspends execution until the specified process termin
int
waitpid(int pid)
{
  acquire(&wait_lock);
  
  struct proc *pp;
  int havekids;
  struct proc *p = myproc();

  for (;;){
    havekids = 0;
    for(pp = proc; pp < &proc[NPROC]; pp++){
      if(pp->pid == pid && pp->parent == p){
        acquire(&pp->lock);
        havekids = 1;

        if(pp->state == ZOMBIE){
          freeproc(pp);
          release(&pp->lock);
          release(&wait_lock);
          return 0;
        }
        release(&pp->lock);
      }
    }

    // No point waiting if we don't have pid's process.
    if(!havekids || killed(p)){
      release(&wait_lock);
      return -1;
    }
    // Wait for a child to exit.
    sleep(p, &wait_lock);  //DOC: wait-sleep
    }
  }


  uint 
  mmap(uint addr, int length, int prot, int flags, int fd, int offset)
  {
    struct proc *p = myproc();
    uint start = addr + MMAPBASE;
    
    struct file* f = 0;
    if (fd != -1){
      f = p->ofile[fd];
    }

    int anony = 0;
    int populate = 0;
    int prot_read = 0;
    int prot_write = 0;
    char* mem = 0;

    if (flags & MAP_ANONYMOUS) anony = 1;
    if (flags & MAP_POPULATE) populate = 1;
    if (prot & PROT_READ) prot_read = 1;
    if (prot & PROT_WRITE) prot_write = 1; 

    if ((!anony) && (fd==-1)) {
      return 0;
    }

    if (f != 0){
      if ( (!(f->readable) && prot_read) || (!(f->writable) && prot_write)) {
        return 0;
      }
    }

    int i = 0;
    while (ma[i].addr != 0 && i < 64) {
      i++;
    }
    if (i == 64) return 0; 

    if (f){
      f = filedup(f);
    }

    ma[i].f = f;
    ma[i].addr = start;
    ma[i].length = length;
    ma[i].offset = offset;
    ma[i].prot = prot;
    ma[i].flags = flags;
    ma[i].p = p;

    if ((!anony) && (populate)){
      f->off = offset;
      uint va = 0;

      for(va=start; va<start+length; va+=PGSIZE){
        mem = kalloc();
        if(!mem) return 0;
        memset(mem, 0, PGSIZE);
        fileread(f, (uint64)mem, PGSIZE);
        if (mappages(myproc()->pagetable, va, PGSIZE, V2P(mem), prot|PTE_U) == -1) return 0;
      }
      return start;
    }

    if ((anony) && (populate)){
      uint va = 0;
      for(va=start; va<start+length; va+=PGSIZE){
        mem = kalloc();
        if(!mem) return 0;
        memset(mem, 0, PGSIZE);
        if (mappages(myproc()->pagetable, va, PGSIZE, V2P(mem), prot|PTE_U) == -1) return 0;
      }
      return start;
    }

    return start;
  }


int 
munmap(uint addr)
{
  struct proc *p = myproc();
  int found = -1;

  for (int i=0;i<64;i++){
    if (addr == ma[i].addr){
      if ((ma[i].p == p) && (ma[i].addr == 0)){
        found = i;
        break;
      }
    }
  }

  if(found == -1){
    return -1;
  }

  uint va = 0;
  pte_t* pte;

  for(va = addr; va < addr+ma[found].length; va += PGSIZE){
    pte = walk(p->pagetable, (uint64)(va), 0);
    if(!pte) continue; // page fault has not been occurred on that address, just remove mmap_area structure.
    if(!(*pte & PTE_V)) continue;
    uint paddr = PTE_ADDR(*pte);
    char *v = (char*)(paddr);
    kfree(v);
    *pte = 0;
  } 
  ma[found].f = 0;
  ma[found].addr = 0;
  ma[found].length = 0;
  ma[found].offset = 0;
  ma[found].prot = 0;
  ma[found].flags = 0;
  ma[found].p = 0;
  return 1;
}