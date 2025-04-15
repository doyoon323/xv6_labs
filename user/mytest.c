#include "user.h"
#include "kernel/types.h"
#define NUM_CHILDREN 5

int main(void)
{       
        
  int pids[NUM_CHILDREN];
  int nice_vals[NUM_CHILDREN] = {10, 20, 25, 30, 35};

  printf("\n===== [EEVDF TEST: START] =====\n");

  for (int i = 0; i < NUM_CHILDREN; i++) {
    int pid = fork();
    if (pid == 0) {
      // 자식 프로세스
      setnice(getpid(), nice_vals[i]);
      printf("[child %d] started with nice = %d\n", getpid(), getnice(getpid()));
      for (volatile int j = 0; j < 50000000; j++);  // busy loop to consume CPU
      exit(0);
    } else {
      pids[i] = pid;
    }
  }

  // 부모: ps 호출하여 상태 확인
  sleep(10);  // 자식들이 실행할 시간 확보
  printf("\n[Parent] === ps output ===\n");
  ps(-1);  // 모든 프로세스에 대한 정보 출력

  // 자식 종료 대기
  for (int i = 0; i < NUM_CHILDREN; i++) {
    waitpid(pids[i]);
  }

  printf("\n===== [EEVDF TEST: END] =====\n");
  exit(0);


        /*
        printf("Testing getnice and setnice value\n");
        int nice = getnice(pid);
        printf("initial nice value : %d\n",nice);
        setnice(pid, 30);
        nice = getnice(pid);
        printf("nice value after setting: %d\n",nice);

        printf("Testing ps\n");
        ps();

        printf("Testing meminfo\n");
        int mem = meminfo();
        printf("available memory: %d\n",&mem); */
        return 0;
    }
