#include "user.h"
#include "stat.h"


int main(void)
{       
        
        int pid = getpid();
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


        printf("\n==== EEVDF Process Info ====\n");
        printf("PID\tSTATE\t\tVRUNTIME\tVDEADLINE\tWEIGHT\tTIMESLICE\tELIGIBLE\n");
        printf("-----------------------------------------------------------------------\n");

        ps(pid);  

        return 0;
    }