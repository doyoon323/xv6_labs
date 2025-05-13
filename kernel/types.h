typedef unsigned int   uint;
typedef unsigned short ushort;
typedef unsigned char  uchar;

/* 
운영체제 등 하드웨어 관련 프로그래밍에서는 데이터 크기를 정확히 지정하는 것이 중요하다.
따라서 "정확한 비트 크기"를 보장하는 타입을 따로 만든것

-> 아키텍처마다 기본 타입 크기가 다를 수 있다.
아래와 같이 한다면 어떤 아키텍처에 실행되더라도 데이터 크기가 일정하게 유지

ex) 아래와 같이 쓴다면 다른 아키텍처 (1바이트가 9비트)에서 한 줄만 고치면 다 돌아가서 일관성 굿~
*/
typedef unsigned char uint8;//8비트 정수 char이지만 숫자로 사용 
typedef unsigned short uint16;
typedef unsigned int  uint32;
typedef unsigned long uint64;

//Page Directory Entry, 가상메모리를 관리하기 위한 페이지테이블 (가상메모리를 실제 메모리로 변환하는 과정, 페이지테이블의 물리적주소를 저장한다?? 라는데 뭐라는거임)
//페이지 디렉토리에 저장되는 64비트의 값
typedef uint64 pde_t;
