Reverse TCP
===========

# 1. 개요
1. 목적
	*

2. 동작

# 2. 함수 설명
1. generate
	* 목적
		* reverse tcp를 위한 설정 생성하고 실제 생성하는 함수 호출
	* 흐름
		* 설정(conf) 변수에 port 번호는 datastore['LPORT']로, host는 datastore['LHOST']로, retry_count는 datastore['ReverseConnectRetries']로 설정하고 reliable은 false로 설정
		* 만약 여분 공간이 있다면, conf의 exitfunk를 datastore['EXITFUNC']로 설정하고 reliable을 true로 변경
		* 설정에 따라 generate_reverse_tcp(conf)를 통해 reverse tcp를 생성

2. generate_reverse_tcp(opts={})
	* 목적
		* reverse tcp 생성 위한 어셈블리 코드 수행
	* 흐름
		* 방향 플래그를 초기화
		* RSP (스택 포인터)가 16바이트로 align 된 것을 보장
		* start 함수를 호출
		* asm_reverse_tcp(opts)를 호출

3. asm_reverse_tcp(opts)
	* 목적
		*
	* 흐름
		* reliable 변수에 conf에 설정된 reliable 값(True/False)을 설정
		* retry_count 변수에 conf에 설정된 retry_count와 1 중 큰 값을 설정
		* encoded_port에 포트 번호를 encoded_host에 IP 주소를 넣고 이를 encoded_host_port로 합침
		* 어셈블리 코드 수행

# 3. 어셈블리 코드의 레이블 설명
1. reverse_tcp
	* 목적
		* WinSock 관련한 라이브러리 로드
	* 흐름
		* 'ws2_32'를 r14로 보내고 이를 stack에 집어 넣음
		* rsp 값을 r14로 보내고 struct WSAData 크기 만큼 스택에 공간 할당 (408 + 8만큼, 여기서 뒤의 8은 alignment를 위함)
		* r13에 rsp 값을 저장 (곧, WSAData의 시작 위치에 해당)
		* r12에 IP/포트 번호(struct sockaddr에 해당)를 넣고 이를 다시 스택에 저장
		* r12에 rsp 값을 넣음
		* r14의 값("ws2_32" 스트링으로의 주소값)을 rcx에 저장 (이는 다음 함수 호출을 위한 인자가 됨)
		* r10d에 kernel32.dll의 LoadLibraryA로의 주소값을 저장
		* 이를 통해 LoadLibraryA("ws2_32")를 수행하여 ws2_32.dll을 로드함 (이 라이브러리는 WinSock과 관련된 라이브러리)
		* r13에 저장된 값(WSAData 시작 주소)을 rdx로 옮기고 0x0101을 스택에 넣고 rcx가 이 값을 가져감(pop 수행)
		* r10d에 ws2_32.dll의 WSAStartup 함수로의 주소값을 저장
		* 그리고 나서 WSAStartup(0x0101, &WSAData)를 호출 (0x0101은 rcx에 저장되어 있고, &WSAData는 rdx에 저장되어 있음)
		* r14에 retry_count 값을 저장
		* create_socket으로 넘어감

2. create_socket
 	* 목적
		* 소켓 생성
	* 흐름
		* rax를 스택에 넣고 초기화하며, r8, r9를 모두 0으로 초기화
		* rax를 1(SOCK_STREAM에 해당)로 만들고 이 값을 rdx(두번째 인자)에 넣음
		* rax를 2(AF_INET에 해당)로 만들고 이를 rcx(첫번째 인자)에 넣음
		* r10d(호출할 함수 주소)에 ws2_32.dll의 WSASocketA 함수 주소를 저장
		* rax(WSASocketA 함수의 return 값, 소켓 번호)를 rdi에 저장
		* try_connect로 넘어감

3. try_connect
	* 목적
		* 대상에 연결(connect)
	* 흐름
		* 16을 스택에 넣고 이를 r8이 가져감(pop)
		* r12의 값(IP/Port 정보, sockaddr 구조체)을 rdx에 저장
		* rdi(소켓)를 rcx에 저장 
		* r10d에 ws2_32.dll의 connect 함수 주소를 저장
		* connect(소켓, &sockaddr, 16)을 호출
		* 만약 연결되면 connected로 넘어감, 연결되지 않았다면, try_connect를 재시도
		* 만약 retry_count만큼 시도했는데 안되면 종료 단계(failure)로 넘어감 

4. failure
	* 목적
		* 연결 실패 시 동작을 정의
	* 흐름
		* exitfunk가 설정되어 있다면 exitfunk를 수행

5. connected
	* 목적
		* 연결되었을 때의 동작을 정의
	* 흐름
		* UUID를 보내게 되어 있다면 전송

6. recv
	* 목적
		* 수신 시, 동작을 정의
	* 흐름
		* 스택에 16바이트만큼 공간을 할당
		* 할당된 공간의 시작 위치를 rdx에 저장
		* r9를 0으로 초기화하고 r8에 4를 저장
		* rcx에 rdi(소켓)를 저장
		* r10d에 ws2_32.dll의 recv 함수 주소를 저장하고 호출
		* 만약 reliable이 정의되어 있다면 (즉, true라면), eax (recv의 반환 값)이 0보다 작으면 cleanup_socket을 호출
