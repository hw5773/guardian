Shellcode 분석
==============

# 1. 개요
![해킹시나리오](https://msdnshared.blob.core.windows.net/media/2017/06/Figure-01.-Infection-cycle-overview.png)

# 2. 상수 정의 (Constant)
## 디렉티브 (Directive)
1. BITS
	* 용도
		* 대상 프로세서의 모드를 명세해 줌
	* 형식
		* BITS XX로 표기되며, XX에는 16, 32, 64가 가능
	* BITS 64 (line 27)
		* 어셈블러에게 프로세서 대상이 64비트임을 알려줌

2. ORG
	* 용도
		* 어셈블러의 출력 코드가 실제 로딩되는 주소값을 의미
	* 형식
		* ORG <addr> 세그먼트 시작으로부터  <addr>만큼 띠어진 곳에 로드됨
	* ORG 0 (line 28)
		* 오프셋이 0임을 표시

3. DEFAULT REL
	* 용도
		* 64비트의 레지스터를 사용하지 않는 명령어가 RIP 인지 아닌지 결정
		* REL이 설정되지 않으면 절대값 사용
	* 형식
		* DEFAULT REL
	* DEFAULT REL
		* RIP 사용한다는 것을 의미

4. SECTION
	* 용도
		* 섹션의 정의
	* 예시
		* SECTION .text .text라는 섹션을 정의

5. GLOBAL
	* 용도
		* 심볼을 다른 모듈에도 알림
	* 예시
		* global payload_start: payload_start라는 심볼이 모든 모듈에게 알려짐

## 매크로 (Macro)
1. PROCESS_HASH SPOOLSV_EXE_HASH (line 35)
	* SPOOLSV_EXE_HASH로 대체

2. MAX_PID (line 36)
	* 최대 PID 값을 0x10000으로 설정

3. WINDOWS_BUILD (line 37)
	* 7601로 설정

4. USE_X86
	* USE_X86이라는 상수 정의
	* 주석에 따르면 그 의미는 x86 페이로드 사용

5. USE_X64
	* USE_X64라는 상수 정의
	* 주석에 따르면 x64 페이로드 사용


# 3. 레이블 흐름 (Labels)

## payload_start
* 목적
	* x86/x64를 판단하여 원하는 작업을 실행

* 흐름
	* ecx = 0
	* 0x41을 binary에 끼워넣는다. 0x41은 x86에서는 inc ecx, x64에서는 rex prefix를 의미한다. inc ecx는 ecx값을 1 증가시키고, rex는 아무 작업도 하지 않는다.
	* ecx값을 1 감소시키고, 0이 아니면 x64_payload_start로 점프한다.(즉, x64인 경우 ecx=-1일 때 점프)
	* x86이면 ret한다.(아무 작업도 실행하지 않음)

## x64_payload_start
* 목적
	* x64일 때 payload를 시작한다.

* 흐름
	* 어셈블러에 64bit 프로세서임을 알린다.
	* SYSCALL_OVERWRITE가 정의되어 있으면 아래 2개의 label을 진행한다.
	* 상수 BITS를 64로 정의

## x64_syscall_overwrite
* 목적
	* handler의 주소값을 LSTAR MSR에 저장

* 흐름
	* IA32_LSTAR MSR의 주소를 ecx에 넣는다. IA32_LSTAR MSR은 syscall이 호출될 때 다음에 실행될 instruction 값을 가지고 있다.
	* IA32_LSTAR MSR 값을 읽는다.
	* rdmsr (LSTAR를 읽음) 읽은 값은 edx에 상위 4바이트가 eax에 하위 4바이트가 저장됨
	* rbx에 절대값 0xffffffffffd00ff8을 대입
	* rbx의 4바이트 뒤에 edx 값을 저장하고, rbx 주소에 eax의 값을 저장
	* x64_syscall_handler의 주소값을 rax에 읽고, rdx에 복사한 뒤, rdx를 4바이트 오른쪽으로 시프트 연산 수행
	* 위 과정을 통해 x64_syscall_handler의 상위 4바이트 주소값은 edx에, 하위 4바이트 주소값은 eax에 저장됨
	* wrmsr 명령어를 통해 LSTAR MSG에 기록하고 ret를 통해 반환

## x64_syscall_handler
* 목적
	* SYSCALL이 호출되었을 때의 처리(이 처리 후 본래 OS의 SYSCALL 처리 루틴으로 점프)
* 흐름
	* swapgs를 호출하여 msr 레지스터의 0xC0000102 (IA32_KERNEL_GS_BASE)의 값을 gs 레지스터와 바꿈 (x86_64에서는 GS 레지스터를 통해 Thread Information Block에 접근할 수 있음)
	* rsp의 값(사용자의 rsp 값)을 적절한 위치에 저장
	* rsp에 커널의 스택 포인터를 저장
	* 스택에 rax, rbx, rcx, rdx, rsi, rdi, rbp, r8, r9, r10, r11, r12, r13, r14, r15를 저장
	* 스택에 값 33 (0x2b)를 넣고 사용자의 스택 포인터를 넣는다. 그리고 r11을 넣고 값 51 (0x33)을 넣은 뒤, rcx를 넣는다. r10의 값을 rcx로 옮긴 뒤, rsp의 값을 8만큼 뺀 다음 rbp를 스택에 넣음.
	* 그 다음 rsp를 0x158만큼 빼고 rsp + 0x80의 주소를 rbp에 넣음
	* rbx, rdi, rsi를 각각 스택에 저장
	* rax에 0xffffffffffd00ff8 (이 주소에 원래의 syscall_handler 주소가 있음)를 넣고, eax가 하위 4바이트, edx가 상위 4바이트 값을 가진 뒤 ecx에 0xc0000082 (LSTAR)에 넣고 wrmsr를 호출
	* sti 명령어로 interrupt flag (IF)를 set하고 x64_kernel_start를 호출
	* x64_kernel_start가 반환된 후, cli 명령어를 통해 IF를 0으로 만들고 저장된 레지스터들을 복원
	* 현재의 스택 포인터 값(커널 스택 포인터)을 IA32_KERNEL_GS_BASE를 기준으로 커널 스택 포인터를 넣는 공간에 저장하고 반대로 사용자 공간의 값을 rsp로 가져옴
	* 그리고나서 swapgs를 통해 본래의 GS 값을 가져옴
	* 마지막으로 원래의 syscall handler로 점프

## x64_kernel_start
* 목적
	* 이후 처리를 위한 사전 수행 (레지스터 저장 등)
* 흐름
	* rsi, r15, r14, r13, r12, rbx, rbp를 저장
	* 현재의 스택포인터(rsp)를 베이스포이터(rbp)로 복사
	* 스택포인터의 마지막 1바이트를 0xFFF0과 and시켜서 ABI(Application Binary Interface, 두 프로그램 모듈 사이의 인터페이스)로 정렬
	* rsp에서 0x20만큼 뺌
	* r14에 x64_kernel_start 주소를 저장
	* x64_find_nt_idt 수행

## x64_find_nt_idt
* 목적
	* KPCR(Kernel Processor Control Region)으로부터 IDT(Interrupt Descriptor Table)를 추출 (Thread Environment Block (TEB) 혹은 Thread Information Block (TIB)의 Environment Pointer에 해당)
* 흐름
	* r15에 gs:0x38인 IDTBase의 주소를 저장
	* 다시 IDTBase 주소값에 4를 더해서 Interrupt Service Routine (ISR) 주소를 얻음
	* 위 주소값을 오른쪽으로 12비트 시프트하고 다시 왼쪽으로 시프트하여 하위 12비트를 0으로 만듬
	* r15의 값에서 0x1000을 빼고, 첫 8바이트를 rsi에 저장
	* 하위 2바이트와 0x5a4d를 비교 (Portable Executable (PE)가 MZ로 시작하는지 확인)
	* 만약 MZ가 발견되지 않으면 발견될 때까지 r15에서 0x1000을 빼고 MZ를 찾는다.

## find_threadlistentry_offset
* 목적
	* ETHREAD 구조체의 ThreadListEntry 필드의 offset을 발견
* 흐름
	* 만약 ETHREAD 구조체가 정적이라면 (ifdef STATIC_ETHREAD_DELTA), 0x420 (ETHREAD_THREADLISTENTRY_OFFSET)을 r12에 저장
	* 만약 static이 아니라면 PSGETCURRENTPROCESS_HASH (PsGetCurrentProcess의 해시값)를 r11d에 저장하고 x64_block_api_direct를 호출
	* PsGetCurrentProcess 함수를 통해 현재 쓰레드의 프로세스로의 포인터 주소를 eax에 저장
	* rax를 rsi에 복사하고, 해당 주소값을 EPROCESS_THREADLISTHEAD_BLINK_OFFSET만큼 더해서 PEPROCESS->ThreadListHead를 찾음
	* KEGETCURRENTTHREAD_HASH를 r11d에 저장하고 x64_block_api_direct를 호출하여 KeGetCurrentThread를 호출하여 rax에 현재 쓰레드에 대한 포인터 값을 가져옴
	* PEPROCESS->ThreadListHead를 rcx에 저장

## _find_threadlistentry_offset_compare_threads
* 목적
	* offset을 찾기위한 과정
* 흐름
	* rax에는 현재 쓰레드에 대한 포인터가 있고, rsi에는 ThreadListHead가 있음. 이 둘을 비교하여 rax가 rsi보다 크면 _find_threadlistentry_offset_walk_threads를 호출
	* 작거나 같은 경우, rdx에 rax + 0x500의 주소값을 저장
	* rdx와 rsi를 비교해서 rdx가 작으면 _find_threadlistentry_offset_walk_threads를 호출
	* rdx가 크거나 같다면, 즉 rax <= rsi <= rdx면 _find_threadlistentry_offset_calc_thread_exit를 호출

## _find_threadlistentry_offset_walk_thread
* 목적
	* list의 다음을 찾고 while을 수행
* 흐름
	* rax > rsi이거나 rdx < rsi인 경우에 호출됨
	* list의 다음을 rsi에 저장
	* rsi와 rcx(list head)를 비교하여 만약 다르면 _find_threadlistentry_offset_compare_threads를 반복 수행
	* 만약 같다면 list에 entry가 더 없다는 뜻이므로, rsi를 r12에 저장

## _find_threadlistentry_offset_calc_thread_exit
* 목적
	* entry의 offset을 반환
* 흐름
	* rsi값(offset)을 r12에 저장

## x64_find_process_name
* 목적
	* 프로세스 이름을 찾음
* 흐름
	* ebx를 0으로 초기화
	* ecx를 0으로 만들고 0x4를 더함
	* 만약 MAX_PID가 정의되어 있어서 ecx의 값이 MAX_PID와 비교해서 ecx가 더 크거나 같으면 x64_kernel_exit를 호출
	* 만약 ecx 값이 MAX_PID보다 작으면 (즉, 정상범위라면) r14를 rdx에 저장하고 ecx를 ebx에 저장한 뒤, PsLookupProcessById를 호출
	* 위 함수는 PID에 대한 포인터 값을 eax에 저장
	* test eax, eax를 통해서 정상 반환되었는지 확인. eax가 0이면 STATUS_SUCCESS가 되어 loop에서 나감. 만약 INVALID하면 _x64_find_process_name_loop_pid를 반복 수행
	* 루프에서 나가면 x64_kernel_start를 rcx에 저장
	* PsGetProcessImageFileName을 수행하여 eax에 실행 파일의 이름을 저장
	* rax를 rsi에 저장하고 x64_calc_hash를 수행하여 r9d에 저장하고 PROCESS_HASH와 비교 (PROCESS_HASH는 공격자가 설정. 기본은 SPOOLSV_EXE_HASH)
	* 위와 비교해서 공격자가 원하는 프로세스의 PID를 찾을때까지 _x64_find_process_name_loop_pid를 반복

## x64_attach_process
* 목적
	* 현재 쓰레드를 process에 attach함
* 흐름
	* r14가 참조하는 값을 rbx에 저장. r14는 EPROCESS이므로 [r14]는 PCB
	* r14+16을 r13에 저장. r14+16은 PCB의 ProfileListHead
	* r13을 rdx에 저장
	* rbx를 rcx에 저장(rcx:PEPROCESS)
	* KeStackAttachProcess 함수 실행(argument: PRKPROCESS process, PRKAPC_STATE ApcState). KEPROCESS는 현재 쓰레드를 PEPROCESS가 가리키는 process의 address space에 attach함. 현재 쓰레드가 이미 attach되어 있으면 ApcState에 현재의 APC를 반환
	* ZwAllocateVirtualMemory를 위한 argument setting
	* rsp에서 0x20을 뺌(shadow stack 예약)
	* ZwAllocateVirtualMemory 함수 실행
	* 함수의 리턴값을 확인하여 0이면 아래로 진행. 0이 아니면 x64_kernel_exit_cleanup 함수 호출.

## x64_memcpy_userland_payload
* 목적
	* userland의 payload 복사
* 흐름
	* [r14]를 rdi에 저장. rdi는 PCB
	* userland_start 주소를 rsi에 저장
	* ecx에 0 저장
	* userland_payload_size 주소를 cx에 더함
	* userland의 size를 cx에 더함. cx는 userland size + payload size
	* esi가 가리키는 곳에 있는 값을 edi로 ecx 갯수만큼 복사(rep movsb:repeat move single byte)

## x64_find_alterable_thread
* 목적
	* 
* 흐름
	* rbx를 rsi에 저장(rsi = EPROCESS)
	* rsi에 EPROCESS_THREADLISTHEAD_BLINK_OFFSET을 더함. rsi는 EPROCESS.ThreadListHead.Blink임
	* rsi를 rcx에 저장(head pointer를 rcx에 저장)

## _x64_find_alertable_thread_loop
* 목적
	* loop를 돌며 alertable thread를 찾음
* 흐름
	* [rcx]를 rdx에 저장. rdx는 다음 list_entry
	* rsi와 rcx를 비교. 같으면 x64_kernel_exit_cleanup으로 이동. 아니면 아래로 진행
	* rdx에서 r12(offset)를 뺌. rdx는 EPROCESS
	* rcx와 rdx값을 스택에 저장
	* PsGetThreadTeb 실행. eax에 thread의 teb 포인터 저장
	* rcx와 rdx값 복구
	* rax가 0인지 체크(TEB가 NULL인지 확인)
	* NULL이면 _x64_find_alertable_thread_skip_next로 이동. 아니면 아래로 진행
	* rax에 TEB.ActivationContextStackPointer를 저장
	* rax 값을 확인하여 0(NULL)이면 _x64_find_alertable_thread_skip_next로 이동. 아니면 아래로 진행
???	* rdx에 ETHREAD_ALERTABLE_OFFSET 저장. rdx값 불명(thread의 state를 확인하는 듯)
	* rdx가 참조하는 값을 eax에 저장
	* eax의 6번째 최하위 비트를 carry flag에 복사
	* carry flag가 1이면 _x64_finnd_alertable_thread_found로 이동. 아니면 아래로 진행

## _x64_find_alertable_thread_skip_next
* 목적
	* 현재 thread를 skip하고 다음 thread를 찾아 loop을 진행
* 흐름
	* [rcx]를 rcx에 저장. rcx는 다음 list_entry
	* _x64_find_alertable_thread_loop으로 이동

## _x64_find_alertable_thread_found
* 목적
	* alertable thread의 pointer를 가져옴
* 흐름
	* rdx에서 ETHREAD_ALERTABLE_OFFSET을 뺌. 따라서, rdx는 ETHREAD
	* rdx를 r12에 저장

## x64_create_apc
* 목적
	* alertable thread를 이용해 실행할 apc 생성
* 흐름
	* edx에 0 저장
	* dl에 0x90 더함
	* ecx에 0 저장
	* ExAllocatePool 함수 실행. Pool을 생성 후 Allocated Block의 포인터를 리턴
	* rax(pool을 참조하는 포인터)를 rcx에 저장	
	* KeInitializeApc의 parameter 설정
	* KeInitializeApc 함수 실행. apc를 초기화. 이때 InjectionShellCode를 넣음
	* KeInsertQueueApc의 parameter 설정
	* KeInsertQueueApc 함수 실행. apc를 queue에 넣음

## x64_kernel_exit_cleanup
* 목적
	* kernel mode에서 나가기 전 작업
* 흐름
	* r13을 rcx에 넣음(rcx=pApcState)
	* KeUnstackDetachProcess 실행. current thread를 process의 address space에서 제거 후 기존의 attach state 복원
	* rbx를 rcx에 넣음(rcx=PEPROCESS)
	* ObDereferenceObject 실행. EPROCESS의 reference count를 1 감소시키고 retention check

## x64_kernel_exit
* 목적
	* kernel mode 탈출
* 흐름
	* rbp를 rsp에 저장(stack 고정)
	* kernel mode 진입 전 스택 상태 복원

## x64_userland_start
* 목적
	* userland 시작
* 흐름
	* x64_userland_start_thread로 점프

## x64_calc_hash
* 목적
	* hash값 계산
* 흐름
	* r9에 0 저장

## x64_calc_hash_loop
* 목적
	* hash값 계산하는 loop
* 흐름
	* eax에 0 저장
	* si의 byte를 eax에 저장(ASCII function name의 다음 byte를 읽음)
	* r9d(hash value)를 13bit만큼 오른쪽으로 rotate
	* al이 'a'인지 비교
	* al이 작으면 _x64_calc_hash_not_lowercase로 이동. 아니면 아래로 진행
	* al에서 0x20 뺌(대문자로 바꿈)

## x64_calc_hash_not_lowercase
* 목적
	* 대문자로 normalize된 hash값의 처리
* 흐름
	* r9d에 eax를 더함(이름의 다음 byte를 더함)
	* al과 ah 비교
	* 같지 않으면 _x64_calc_hash_loop로 이동. 아니면 return

## x64_block_find_dll
* 목적
	* 원하는 dll을 찾기 위해 PEB에 로드된 모듈 정보를 가져옴
* 흐름
	* edx에 0 저장
	* rdx에 [gs:rdx+96] 저장
	* rdx에 [rdx+24] 저장. rdx는 PEB->Ldr. Ldr은 프로세스에 로드된 모듈에 대한 정보를 가진 구조체임
	* rdx에 [rdx+32] 저장. rdx는 InMemoryOrder list. InMemoryOrder list는 메모리에 위치한 모듈 순서를 나타냄

## x64_block_find_dll_next_mod
* 목적
	* 리스트를 통해 모듈을 찾아 이름과 길이 불러옴
* 흐름
	* rdx에 [rdx]를 저장.  rdx는 다음 모듈이 됨
	* rsi에 [rdx + 80]을 저장. rsi는 PEB->ProcessParameter.unicodestring을 가리킴
	* rcx에 [rdx + 74]를 저장. rcx는 string length
	* r9d에 0 저장

## _x64_block_find_dll_loop_mod_name
* 목적
	* 원하는 모듈의 이름의 해시값을 비교하기 위해 대문자로 바꿈
* 흐름
	* eax에 0 저장
	* unicode string의 다음 byte를 읽음
	* al과 'a'값 비교
	* al이 작으면 _x64_block_find_dll_not_lowercase로 이동. 아니면 아래로 진행
	* al에서 0x20 뺌. 대문자로 normalize

## _x64_block_find_dll_not_lowercase
* 목적
	* 대문자로 바꾸어 해시값 비교하는 과정
* 흐름
	* r9d값을 rotate
	* r9d에 eax 더함(이름의 다음 byte를 더함)
	* ecx를 1씩 줄여가며 0인지 체크. 0이 되기 전까지 _x64_block_find_dll_loop_mod_name 반복
	* r9d와 r11d 비교
	* 같지 않으면 _x64_block_find_dll_next_mod로 이동. 같으면 아래로 진행
	* r15에 [rdx+32]를 저장한 후 return. r15에는 dll의 actual VA가 있을 것으로 추정됨


## x64_block_api_direct
* 목적
	* 함수 호출
* 흐름
	* r15값을 rax에 저장(이 때, r15에 있는 값은 PE 구조체의 가장 첫부분. 즉, IMAGE_DOS_HEADER 구조체)
	* 기존의 parameter를 스택에 저장
	* rax값을 rdx에 저장
	* e_lfanew를 eax에 저장(e_lfanew는 IMAGE_NT_HEADERS의 offset(RVA))
	* rdx(PE 구조체의 시작 주소)를 rax(offset)에 더함. 따라서 rax는 IMAGE_NT_HEADERS의 주소를 가짐
	* rax+136의 값(IMAGE_NT_HEADERS->IMAGE_OPTIONAL_HEADER->DataDirectory[0]에 있는 IMAGE_EXPORT_DIRECTORY 구조체의 RVA)을 eax에 저장
	* rdx를 rax에 더한다. 이제 rax는 IMAGE_EXPORT_DIRECTORY 구조체를 가리킴(IMAGE_EXPORT_DIRECTORY는 EAT(Export Address Table)에 대한 정보를 담고 있는 구조체)
	* 스택에 rax(EAT) 저장
	* NumberOfNames(이름을 갖는 함수 갯수)를 ecx에 저장
	* AddressOfNames(함수 이름 주소 배열)을 r8d에 저장(역시 RVA값들이 저장되어 있음)
	* r8에 rdx를 더함. 이제 r8은 함수 이름 주소를 가짐

## x64_block_api_direct_get_next_func
* 목적
	* 함수 이름을 이용한 해시값을 비교하며 원하는 함수를 찾음. 배열의 뒤에서부터 비교.
* 흐름
	* rcx를 1 감소
	* esi에 다음 이름의 주소(RVA)를 넣음.
	* rsi에 rdx를 더함. 이제 rsi는 다음 이름의 주소를 가짐
	* x64_calc_hash를 호출하여 해시값 계산
	* r9d와 r11d 비교
	* 0이 아니면(다르면) x64_block_api_direct_get_next_func로 돌아가고 0이면(같으면) 밑으로 진행

## x64_block_api_direct_finsih
* 목적
	* 원하는 함수의 실제 주소를 찾음
* 흐름
	* 스택에서 EAT를 꺼내어 rax에 저장
	* AddressOfNameOrdinal(ordinal 배열의 주소(RVA))를 r8d에 저장
	* r8에 rdx를 더함. 이제 r8은 oridnal 배열의 주소
	* 해당 함수의 이름에 해당하는 ordinal index를 cx에 저장
	* r8d에 AddressOfFunctions의 RVA를 저장
	* r8에 rdx를 더함. 이제 r8은 AddressOfFunctions의 주소
	* cx에 저장했던 ordinal index를 이용하여 원하는 함수의 RVA를 가져와 eax에 저장
	* rax에 rdx를 더함. 이제 rax는  원하는 함수의 actual VA
	* 스택에서 원래값을 복원
	* 복원했던 return address를 다시 스택에 push
	* rax로 이동(즉, 그 함수를 실행. 이 함수가 실행된 뒤에는 다시 return address가 pop될 것임)

## x64_userland_start_thread
* 목적
	* userland의 payload를 실행해 줄 thread를 생성
* 흐름
	* 스택에 기존의 데이터 저장
	* Kernel32.dll를 찾아 r15에 주소 저장
	* ecx에 0 저장
	* CreateThread 함수 실행을 위한 parameter 설정
	* CreateThread 함수 실행. 호출한 process의 VA space에서 실행되는 thread를 생성. 여기서 thread의 start address로 userland_payload의 주소가 들어감. 따라서 원하는 payload를 실행 가능하게 됨
	* 레지스터 복원 후 return
	
## userland_payload_size
* 목적
	* payload size 설정
* 흐름
	* db 명령어를 이용하여 숫자 그대로 넣는다

## userland_payload
* 목적
	* 원하는 동작을 발생시키기 위한 payload를 넣는 장소

# 4. 참고

## 디렉티브 (directives)
* 어셈블러에게 변수의 데이터 형이 무엇인지 알려주거나 매크로를 만들 때 사용
* 소스코드의 흐름을 조절하는 명령어
