# Honeycomb Beacon Message Format

* Honeycomb receive packet
  > BTHP || BEACON

* BTHP Header
  * version: version
  * hdrLen: header length
  * dataLen: data length
  * proxyId: proxy ID
  * additional headers: type, length, data. Terminated by a header with
    `type = 0` & `length = 0`. Contains the beacon, proxy, and dst IPs. These
    additiona BTHP headers are different from the additional beacon headers
    below.
  * First packet: 뒤에 따라오는 길이가 32 bytes이면 BEACON version 1을 나타내고, 그렇지 않으면
version 2를 나타냄. 이 때, version 2로 보낼 패킷 길이 (packet size) 값을 보냄

* encryption: uses the xtea algorithm, but the key is generated at the Honeycomb
  instance and sent back in the clear.

* BEACON Version 1
  * 데이터는 암호화되서 옴
  * 데이터 구성
    > MAC 주소 (17 bytes) || UP Time (8 bytes)

* BEACON Version 2
  * 데이터는 암호화되서 옴
  * 데이터 구성
    > BEACON 헤더 (version (2 bytes) || os (2 bytes)) || 압축된 데이터
    > (version >= 23인 경우)

    > BEACON 헤더 (version (2 bytes) || os (2 bytes)) || 데이터

* 위 데이터 구성 (TLV 형식)
  > type (2 bytes) || length (2 bytes) || length 길이 만큼의 string
  * type 1: MAC 주소
  * type 2: UP time
  * type 3: Process list
  * type 4: ipconfig
  * type 5: netstat -rn
  * type 6: netstat -an
  * type 7: next beacon

* OS 정보
  * 10: Windows
  * 20: Linux-x86
  * 30: Solaris-SPARC
  * 31: Solaris-x86
  * 40: MikroTik-MIPS
  * 41: MikroTik-MIPSEL
  * 42: MikroTik-x86
  * 43: MikroTik-PPC
  * 50: Ubiquiti-MIPS
  * 61: AVTech-ARM
  * 1: Windows
  * 2: Linux-x86
  * 3: Solaris-NFI
  * 5: MikroTik-NFI
