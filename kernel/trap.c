#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"
#include "file.h"


struct spinlock tickslock;
uint ticks;

extern struct proc proc[];

extern char trampoline[], uservec[], userret[];

// in kernelvec.S, calls kerneltrap().
void kernelvec();

extern int devintr();

void
trapinit(void)
{
  initlock(&tickslock, "time");
}

// set up to take exceptions and traps while in the kernel.
void
trapinithart(void)
{
  w_stvec((uint64)kernelvec);
}

//
// handle an interrupt, exception, or system call from user space.
// called from trampoline.S
//
void
usertrap(void)
{
  int which_dev = 0; // unint64 안 쓰는 이유 -> 수가 작아서 0~1,2..? 

  if((r_sstatus() & SSTATUS_SPP) != 0)
    panic("usertrap: not from user mode");

  // send interrupts and exceptions to kerneltrap(),
  // since we're now in the kernel.
  w_stvec((uint64)kernelvec); //traphandler 를 kernelvec으로 설정. 이후 trap은 kernaltrap()으로 가야한다(init -> trampoline을 거쳐 usertrap으로 가다가)

  struct proc *p = myproc();
  
  // save user program counter.
  p->trapframe->epc = r_sepc(); //trap시점의 유저모드 pc 저장, 유저모드로 돌아갈 주소
  

  //PA4 
  if (r_scause() == 13 || r_scause() == 15) {  
    uint64 va = r_stval();
    struct proc *p = myproc();
    if (pgfault_handler(va) == 0) {
        return;
    }
    setkilled(p);
}


  if(r_scause() == 8){
    // system call

    if(killed(p))
      exit(-1);

    // sepc points to the ecall instruction,
    // but we want to return to the next instruction.
    p->trapframe->epc += 4;
    //trap발생시점 코드(init의 경우, initCode.S의 ecall)에서 +4byte하면 바로 다음줄로 돌아가겠죠?
    
    // an interrupt will change sepc, scause, and sstatus,
    // so enable only now that we're done with those registers.
    intr_on();

    syscall(); //a7에 있는 syscall 호출 
  } else if((which_dev = devintr()) != 0){
    // ok
  } else {
    printf("usertrap(): unexpected scause 0x%lx pid=%d\n", r_scause(), p->pid);
    printf("            sepc=0x%lx stval=0x%lx\n", r_sepc(), r_stval());
    setkilled(p);
  }

  if(killed(p))
    exit(-1);

 
   // give up the CPU if this is a timer interrupt. -> 1 tick마다 처리
if (which_dev == 2 && p && p->state == RUNNING) {
  p->runtime++;                          // 실제 실행 시간 1 tick 증가
  p->vruntime += (1024 / p->weight);       // 우선순위 보정된 vruntime 증가
  p->timeslice--;                        // 남은 timeslice 감소
//  printf("DEBUG: Timer interrupt for proc[%d]: runtime=%lu, vruntime=%lu, timeslice=%d\n",
     //    p->pid, p->runtime, p->vruntime, p->timeslice);

  if (p->timeslice == 0) {
    // 현재 프로세스 p의 내부 필드 업데이트를 위해 p->lock은 이미 잡혀 있다고 가정합니다.
    // (즉, usertrap() 타이머 인터럽트 처리 시작 전에 p->lock은 이미 제대로 잡힌 상태여야 함)
    p->vdeadline = p->vruntime + (5 * 1024 / p->weight);

    p->timeslice = 5;                      // 다음 라운드를 위해 재설정
  //  printf("DEBUG: proc[%d] timeslice exhausted, vdeadline recalculated: %lu. Updating eligible...\n",
   //        p->pid, p->vdeadline);

    // --- eligible 계산 시작 ---
    uint64 v0 = (uint64)-1;  // 대상 프로세스 중 최소 vruntime을 구하기 위해 초기값으로 최댓값
    int total_weight = 0;
    struct proc *pr;

    // 1. 대상 프로세스들 (RUNNABLE 또는 RUNNING)의 v0와 total_weight 계산
    for (int i = 0; i < NPROC; i++) {
      pr = &proc[i];
      if (pr == p) {
        // 현재 프로세스 p는 이미 락이 잡혀 있음.
        if (pr->state == RUNNABLE || pr->state == RUNNING) {
          if (pr->vruntime < v0)
            v0 = pr->vruntime;
          total_weight += pr->weight;
        }
      } else {
        acquire(&pr->lock);
        if (pr->state == RUNNABLE || pr->state == RUNNING) {
          if (pr->vruntime < v0)
            v0 = pr->vruntime;
          total_weight += pr->weight;
        }
        release(&pr->lock);
      }
    }
    //printf("DEBUG: Eligible Calc Step1 complete: v0=%lu, total_weight=%d\n", v0, total_weight);

    // 2. 좌변: ∑((vruntime - v0) * weight) 계산
    uint64 left_sum = 0;
    for (int i = 0; i < NPROC; i++) {
      pr = &proc[i];
      if (pr == p) {
        if (pr->state == RUNNABLE || pr->state == RUNNING)
          left_sum += (pr->vruntime - v0) * pr->weight;
      } else {
        acquire(&pr->lock);
        if (pr->state == RUNNABLE || pr->state == RUNNING)
          left_sum += (pr->vruntime - v0) * pr->weight;
        release(&pr->lock);
      }
    }
    //printf("DEBUG: Eligible Calc Step2 complete: left_sum=%lu\n", left_sum);

    // 3. 각 대상 프로세스에 대해 eligible 결정
    for (int i = 0; i < NPROC; i++) {
      pr = &proc[i];
      if (pr == p) {
        if (pr->state == RUNNABLE || pr->state == RUNNING) {
          uint64 right_term = (pr->vruntime - v0) * total_weight;
          // p는 현재 프로세스이므로 직접 업데이트:
          p->eligible = (left_sum >= right_term) ? 1 : 0;
      //    printf("DEBUG: Eligible Calc Step3: proc[%d]: vruntime=%lu, right_term=%lu, eligible=%d (current p)\n",
            //     p->pid, p->vruntime, right_term, p->eligible);
        }
      } else {
        acquire(&pr->lock);
        if (pr->state == RUNNABLE || pr->state == RUNNING) {
          uint64 right_term = (pr->vruntime - v0) * total_weight;
          pr->eligible = (left_sum >= right_term) ? 1 : 0;
        //  printf("DEBUG: Eligible Calc Step3: proc[%d]: vruntime=%lu, right_term=%lu, eligible=%d\n",
          //       pr->pid, pr->vruntime, right_term, pr->eligible);
        } else {
          pr->eligible = 0;
        }
        release(&pr->lock);
      }
    }
    // --- eligible 계산 끝 ---
    release(&p->lock);
    yield();
  }
}
usertrapret();
}

      

// return to user space
//
void
usertrapret(void)
{
  struct proc *p = myproc();

  // we're about to switch the destination of traps from
  // kerneltrap() to usertrap(), so turn off interrupts until
  // we're back in user space, where usertrap() is correct.
  intr_off();

  // send syscalls, interrupts, and exceptions to uservec in trampoline.S
  uint64 trampoline_uservec = TRAMPOLINE + (uservec - trampoline); // uservec의 정확한 가상 주소
  w_stvec(trampoline_uservec);



  // set up trapframe values that uservec will need when
  // the process next traps into the kernel.
  p->trapframe->kernel_satp = r_satp();         // kernel page table
  p->trapframe->kernel_sp = p->kstack + PGSIZE; // process's kernel stack
  p->trapframe->kernel_trap = (uint64)usertrap;
  p->trapframe->kernel_hartid = r_tp();         // hartid for cpuid()

  // set up the registers that trampoline.S's sret will use
  // to get to user space.
  
  // set S Previous Privilege mode to User.
  unsigned long x = r_sstatus();
  x &= ~SSTATUS_SPP; // clear SPP to 0 for user mode
  x |= SSTATUS_SPIE; // enable interrupts in user mode
  w_sstatus(x);

  // set S Exception Program Counter to the saved user pc.
  w_sepc(p->trapframe->epc);
//trap 당시 user가 epc에 저장된다.

  // tell trampoline.S the user page table to switch to.
  uint64 satp = MAKE_SATP(p->pagetable);



  // jump to userret in trampoline.S at the top of memory, which 
  // switches to the user page table, restores user registers,
  // and switches to user mode with sret.
  uint64 trampoline_userret = TRAMPOLINE + (userret - trampoline);
  ((void (*)(uint64))trampoline_userret)(satp);
}

// interrupts and exceptions from kernel code go here via kernelvec,
// on whatever the current kernel stack is.
void 
kerneltrap()
{
  int which_dev = 0;
  uint64 sepc = r_sepc();
  uint64 sstatus = r_sstatus();
  uint64 scause = r_scause();
  
  if((sstatus & SSTATUS_SPP) == 0)
    panic("kerneltrap: not from supervisor mode");
  if(intr_get() != 0)
    panic("kerneltrap: interrupts enabled");

  if((which_dev = devintr()) == 0){
    // interrupt or trap from an unknown source
    printf("scause=0x%lx sepc=0x%lx stval=0x%lx\n", scause, r_sepc(), r_stval());
    panic("kerneltrap");
  }

  // give up the CPU if this is a timer interrupt.
  if(which_dev == 2 && myproc() != 0)
    yield();

  // the yield() may have caused some traps to occur,
  // so restore trap registers for use by kernelvec.S's sepc instruction.
  w_sepc(sepc);
  w_sstatus(sstatus);
}

void
clockintr()
{
  if(cpuid() == 0){
    acquire(&tickslock);
    ticks++;
    wakeup(&ticks);
    release(&tickslock);
  }

  // ask for the next timer interrupt. this also clears
  // the interrupt request. 1000000 is about a tenth
  // of a second.
  w_stimecmp(r_time() + 100000);
}

// check if it's an external interrupt or software interrupt,
// and handle it.
// returns 2 if timer interrupt,
// 1 if other device,
// 0 if not recognized.
int
devintr()
{
  uint64 scause = r_scause();

  if(scause == 0x8000000000000009L){
    // this is a supervisor external interrupt, via PLIC.

    // irq indicates which device interrupted.
    int irq = plic_claim();

    if(irq == UART0_IRQ){
      uartintr();
    } else if(irq == VIRTIO0_IRQ){
      virtio_disk_intr();
    } else if(irq){
      printf("unexpected interrupt irq=%d\n", irq);
    }

    // the PLIC allows each device to raise at most one
    // interrupt at a time; tell the PLIC the device is
    // now allowed to interrupt again.
    if(irq)
      plic_complete(irq);

    return 1;
  } else if(scause == 0x8000000000000005L){
    // timer interrupt.
    clockintr();
    return 2;
  } else {
    return 0;
  }
}




int page_fault_handler(uint addr) 
{
  struct proc *p = myproc();
  int found = -1;

  struct mmap_area *ma;
  for (int i = 0; i < 64; i++) {
    ma = p->mmap_areas[i];
    if (ma == 0) continue;  

    if ((ma->addr + ma->length) > addr && addr >= ma->addr) {
        if (ma->p == p && ma->addr != 0) {
            found = i;
            break;
        }
    }
}
  if(found == -1) return -1;

  int anony = 0;
  int prot_write = 0;
  char* mem = 0;


  if (ma[found].flags & MAP_ANONYMOUS) anony = 1;
  if (ma[found].prot & PROT_WRITE) prot_write = 1; 
  if (prot_write == 0) return -1;

  uint start = ma[found].addr;
  uint length = ma[found].length;
  uint va = 0;

  if(!anony) {
    struct file* f = ma[found].f;
    f->off = ma[found].offset;
    for(va=start; va<start+length; va+=PGSIZE){
      if ((va <= addr) && (addr < va + PGSIZE)){       
        mem = kalloc();
        if(!mem) return 0;
        memset(mem, 0, PGSIZE);
        fileread(f, (uint64)mem, PGSIZE);
        int prots = ma[found].prot | PTE_U;
        if (prot_write) prots = prots | PTE_W;
        if (mappages(myproc()->pagetable, va, PGSIZE, V2P(mem), prots) == -1) return 0;
      }
      f->off+=PGSIZE;
    }
  }
  else{
    for(va=start; va<start+length; va+=PGSIZE){
      if ((va <= addr) && (addr < va + PGSIZE)){  
        mem = kalloc();
        if(!mem) return 0;
        memset(mem, 0, PGSIZE);
        int prots = ma[found].prot | PTE_U;
        if (prot_write) prots = prots | PTE_W;
        if (mappages(myproc()->pagetable, va, PGSIZE, V2P(mem), prots) == -1) return 0;
      }
    }
  }
  return 0;
}