// 과제를 하기 위해 우연히 필자의 깃허브로
// 흘러 들어온 BoB 멘티들을 위해 모든 주석을 남깁니다.

/*
	과제 내용
	- 조건 : TCP 패킷만 출력한다. (Data가 0이라도 출력한다!) (ETH+IP+TCP+DATA로 구성되어있다!)
	① Ethernet Header의 Source MAC Address + Destination MAC Address
	② IP Header의 Source IP + Destination IP
	③ TCP Header의 Source Port + Destination Port
	④ Payload(Data)의 hexadecimal value (최대 16바이트 까지만!)
*/


// 패킷 관련 핸들링을 위해 pcap 라이브러리를 추가합니다.
#include <pcap.h>
// printf를 사용하여 화면 출력을 하기 위해 Standard Input/Output 관련 라이브러리를 추가합니다.
#include <stdio.h>
// 패킷 헤더 구조체 모음집을 컴파일 시, 현재 디렉터리 내 파일로 불러옵니다.
#include "libnet-headers.h"

// 명령을 잘못 입력 했을 때 아래 함수를 통해 사용법을 알려줍니다.
void usage() {
	// 프로그램 사용 시, pcap-test <인터페이스 코드> 를 입력하도록 합니다.
	// 본인의 <인터페이스 코드>는 ifconfig 명령어 입력 시 확인 가능합니다.
    printf("syntax: pcap-test <interface>\n");
	// 예시를 들어줍니다.
    printf("sample: pcap-test wlan0\n");
}

// 프로그램의 시작 함수입니다.
int main(int argc, char* argv[]) {
	// 만일, 파라미터를 하나도 입력하지 않거나, 1개보다 많이 입력 하였을 경우
    if (argc != 2) {
		// 사용법을 출력합니다.
        usage();
		// 프로그램을 강제 종료시킵니다.
        return -1;
    }

	// 디바이스 정보에 입력받은 인터페이스 ID를 담습니다.
    char* dev = argv[1];
	// 에러 정보를 담을 버퍼를 준비합니다.
    char errbuf[PCAP_ERRBUF_SIZE];
	// 인터페이스로 들어오는 패킷이 핸들러를 거치도록 통로를 연결 시켜줍니다.
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	// 핸들러 연결에 실패했을 경우
    if (handle == nullptr) {
		// 실패 메시지를 띄웁니다.
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
		// 프로그램을 강제 종료합니다.
        return -1;
    }
	// 반복문이 돌아가기 전에, 미리 아래에서 사용 될 버퍼를 빼서
	// 반복문이 돌아가면서 계속해서 생성하지 않게하여
	// 성능을 쥐꼬리에 묻은 먼지 털 만큼 향상시킵니다.
	
	// 패킷 헤더 정보를 담을 변수를 생성합니다.
	struct pcap_pkthdr* header;
	// 패킷 내용을 담을 변수를 생성합니다.
    const u_char* packet;
	// libnet에서 미리 지정한 이더넷 헤더 구조체를 이용하여 손쉽게 이더넷 헤더를 담을 변수를 생성합니다.
	struct libnet_ethernet_hdr* ethHeader;
	// libnet에서 미리 지정한 IP 헤더 구조체를 이용하여 손쉽게 IP 헤더를 담을 변수를 생성합니다.
	struct libnet_ipv4_hdr* ipHeader;
	// libnet에서 미리 지정한 TCP 헤더 구조체를 이용하여 손쉽게 TCP 헤더를 담을 변수를 생성합니다.
	struct libnet_tcp_hdr* tcpHeader;
	// 페이로드 정보를 담을 변수를 선언합니다.
	const u_char *payload;
	// IP 계산 시 사용 될 버퍼를 미리 생성 해 둡니다.
	char buf[32] = {0,};
	// 아래 구문을 사용자가 멈출 때 까지 반복합니다.
    while (true) {
		// 패킷을 수집합니다.
        int res = pcap_next_ex(handle, &header, &packet);
		// 수집된 패킷이 없다면, while문의 처음으로 돌아갑니다.
        if (res == 0) continue;
		// 패킷 수집 도중 오류가 생겼을 경우
        if (res == -1 || res == -2) {
			// 오류 정보를 출력하고
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			// while 반복문을 빠져나와 프로그램을 종료합니다.
            break;
        }
		// 수집된 패킷이 있다면, 해당 패킷을 이더넷 헤더 크기에 맞게 잘라서 이더넷 헤더 변수에 넣습니다.
		ethHeader = (struct libnet_ethernet_hdr*) packet;
		// 패킷 구조 : https://t1.daumcdn.net/thumb/R720x0/?fname=http://t1.daumcdn.net/brunch/service/user/axm/image/tpw3kz_WNH67954CF8lZmgYBPV8.png
		// [이더넷][IP][TCP][Payload]
		// 이더넷 헤더 속의 이더넷 타입을 네트워크 바이트 오더에 맞추어(ntohs) 해당 값이 IP를 뜻하는지 확인합니다.
		if(ntohs(ethHeader->ether_type) == ETHERTYPE_IP) {
			// IP통신이 맞다면, 방금 읽었던 이더넷 헤더를 지나 패킷의 그 다음부분을 IP 헤더 크기에 맞게 잘라서 IP 헤더 변수에 넣습니다.
			ipHeader = (struct libnet_ipv4_hdr*) (packet + sizeof(struct libnet_ethernet_hdr));
			// IP 헤더 속의 프로토콜 타입이 TCP인지 확인합니다.
			if(ipHeader -> ip_p == IPPROTO_TCP) {
				// 프로토콜 타입이 TCP가 맞을 경우, 지금까지 읽었던 이더넷, IP 헤더를 지나 패킷의 그 다음 부분을 TCP 헤더 크기에 맞게 잘라서 TCP 헤더 변수에 넣습니다.
				tcpHeader = (struct libnet_tcp_hdr*) (packet + sizeof(struct libnet_ethernet_hdr)+sizeof(struct libnet_ipv4_hdr));
				// 프로토콜 뒷 부분이 페이로드 영역이므로, 지금까지 읽었던 이더넷, IP, TCP 헤더를 지나 패킷의 그 다음 부분을 페이로드로 지정합니다.
				payload = (u_char *)(packet + sizeof(struct libnet_ethernet_hdr)+sizeof(struct libnet_ipv4_hdr) +sizeof(struct libnet_tcp_hdr));
				
				// TCP/IP 통신만 출력하는 것이 과제였으므로, IP만 출력합시다.
				printf("┌──┐\n");
				printf("│IP│\n");
				printf("│　└───────────────────────────────────┐\n");
				// 출발지 MAC 주소를 출력합니다.
				printf("│ Src MAC Address : %02x-%02x-%02x-%02x-%02x-%02x\n", ethHeader->ether_shost[0], ethHeader->ether_shost[1], ethHeader->ether_shost[2], ethHeader->ether_shost[3], ethHeader->ether_shost[4], ethHeader->ether_shost[5]);
				// 목적지 MAC 주소를 출력합니다.
				printf("│ Des MAC Address : %02x-%02x-%02x-%02x-%02x-%02x\n", ethHeader->ether_dhost[0], ethHeader->ether_dhost[1], ethHeader->ether_dhost[2], ethHeader->ether_dhost[3], ethHeader->ether_dhost[4], ethHeader->ether_dhost[5]);
				// 출발지 IP 주소를 출력합니다.
				printf("│ Src IP Address : %s\n", inet_ntop(AF_INET,&ipHeader->ip_src,buf,sizeof(buf)));
				// 목적지 IP 주소를 출력합니다.
				printf("│ Des IP Address : %s\n", inet_ntop(AF_INET,&ipHeader->ip_dst,buf,sizeof(buf)));
				// 출발지 Port를 출력합니다.
				printf("│ Src port : %d\n", ntohs(tcpHeader->th_sport));
				// 목적지 Port를 출력합니다.
				printf("│ Des port : %d\n", ntohs(tcpHeader->th_dport));
				// 페이로드를 출력합니다.
				printf("│ Payloads : %16x\n", payload);
				// 총 바이트 수를 출력합니다.
				printf("│ Total %u bytes\n", header -> caplen);
				printf("└──────────────────────────────────────┘\n");

			}
		}
    }
	// 핸들러를 닫습니다.
    pcap_close(handle);
}
