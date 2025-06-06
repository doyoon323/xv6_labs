#!/usr/bin/perl -w

# **** make 명령이 xv6를 빌드할 때 makefile이 자동으로 usys.pl을 실행해서
# usys.S 파일을 만든다, 그리고 user program과 링크됨, user에서 syscall 할때마다 이 파일이 실행**** 

#sum : syscall wrapper 인~ 

# Generate usys.S, the stubs for syscalls.

print "# generated by usys.pl - do not edit\n";

print "#include \"kernel/syscall.h\"\n";#13번 줄이 가능토록

sub entry {
    my $name = shift; #syscall이름을 받아와서 name에 저장 
    print ".global $name\n"; # ex) .global fork -> fork라벨을 전역 심볼로 
    print "${name}:\n"; #어셈블리 함수 라벨 정의 -> fork:
    print " li a7, SYS_${name}\n"; #a7에 sys_name을 저장 -> kernerl/syscall.h에 정의 
    print " ecall\n"; #ecall : 현재 모드에서 OS(kernerl)로 trap 발생 :: 커널에서 syscall보고 판단   
    print " ret\n"; #syscall(ecall) 처리 후 돌아올 때 실행되는 명령어 
}
	
entry("fork");
entry("exit");
entry("wait");
entry("pipe");
entry("read");
entry("write");
entry("close");
entry("kill");
entry("exec");
entry("open");
entry("mknod");
entry("unlink");
entry("fstat");
entry("link");
entry("mkdir");
entry("chdir");
entry("dup");
entry("getpid");
entry("sbrk");
entry("sleep");
entry("uptime");

#PA1 
entry("getnice");
entry("setnice");
entry("ps");
entry("meminfo");
entry("waitpid");

entry("mmap");
entry("munmap");

entry("freemem");
