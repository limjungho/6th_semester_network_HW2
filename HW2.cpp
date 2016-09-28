#include "pcap.h"

#include <stdio.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <stdlib.h>

#pragma comment (lib, "wpcap.lib")
#pragma comment (lib, "ws2_32.lib" )
#pragma comment(lib, "iphlpapi.lib")
void print_arp_result(DWORD RetVal, ULONG& MacAddr, ULONG PhysAddrLen);

int main(int argc, char **argv) {

	DWORD VictimRetVal;
	DWORD GatewayRetVal;
	IPAddr VictimIp = 0;	/* victim ip */
	IPAddr GatewayIp = 0;	/* gateway ip */
	IPAddr SrcIp = 0;    /* default for src ip */
	ULONG SrcMacAddr[2];
	ULONG VictimMacAddr[2];
	ULONG GateMacAddr[2];       /* for 6-byte hardware addresses */
	ULONG PhysAddrLen = 6;  /* default to length of six bytes */

	char *VictimIpString = NULL;
	char *GatewayIpString = NULL;
	char *SrcIpString = NULL;
	unsigned int i;

	VictimIpString = argv[1];
	if (VictimIpString == NULL) {
		printf("Victim Ip Error\n");
		exit(0);
	}
	VictimIp = inet_addr(VictimIpString);

	GatewayIpString = "192.168.0.1";
	GatewayIp = inet_addr(GatewayIpString);

	printf("Sending ARP request for Gateway IP address: %s\n", GatewayIpString);

	SrcIpString = "192.168.0.3";
	SrcIp = inet_addr(SrcIpString);

	memset(&GateMacAddr, 0xff, sizeof(GateMacAddr)); //Gateway로 BroadCasting
	memset(&VictimMacAddr, 0xff, sizeof(VictimMacAddr)); //Victim으로 BroadCasting

	GatewayRetVal = SendARP(GatewayIp, SrcIp, &GateMacAddr, &PhysAddrLen); //send arp request to gateway

	print_arp_result(GatewayRetVal, *GateMacAddr, PhysAddrLen); //Gateway Macaddress 출력

	VictimRetVal = SendARP(VictimIp, SrcIp, &VictimMacAddr, &PhysAddrLen); //send arp request to victim

	print_arp_result(VictimRetVal, *VictimMacAddr, PhysAddrLen); //Victim Macaddress 출력
	

	return 0;

}

void print_arp_result(DWORD RetVal, ULONG& MacAddr, ULONG PhysAddrLen) {

	BYTE *bPhysAddr;
	unsigned int i;

	if (RetVal == NO_ERROR) {
		//printf("%s\n", GateMacAddr);

		bPhysAddr = (BYTE *)& MacAddr;
		if (PhysAddrLen) {
			printf("Gateway Mac Address : ");
			for (i = 0; i < (int)PhysAddrLen; i++) {
				if (i == (PhysAddrLen - 1))
					printf("%.2X\n", (int)bPhysAddr[i]);
				else
					printf("%.2X-", (int)bPhysAddr[i]);
			}
		}
		else
			printf
			("Warning: SendArp completed successfully, but returned length=0\n");

	}
	else {
		printf("Error: SendArp failed with error: %d", RetVal);
		switch (RetVal) {
		case ERROR_GEN_FAILURE:
			printf(" (ERROR_GEN_FAILURE)\n");
			break;
		case ERROR_INVALID_PARAMETER:
			printf(" (ERROR_INVALID_PARAMETER)\n");
			break;
		case ERROR_INVALID_USER_BUFFER:
			printf(" (ERROR_INVALID_USER_BUFFER)\n");
			break;
		case ERROR_BAD_NET_NAME:
			printf(" (ERROR_GEN_FAILURE)\n");
			break;
		case ERROR_BUFFER_OVERFLOW:
			printf(" (ERROR_BUFFER_OVERFLOW)\n");
			break;
		case ERROR_NOT_FOUND:
			printf(" (ERROR_NOT_FOUND)\n");
			break;
		default:
			printf("\n");
			break;
		}
	}
	
}