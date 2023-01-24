#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>	
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>	
// parsing the packet using 2 different OOTB structs and one custom useful struct 
void packetParse(u_char *, const struct pcap_pkthdr *, const u_char *); 
// printing the required components of each tcp packet
void packetPrint(const u_char *, const struct pcap_pkthdr *);
// printing the data (hexa format)
void packetPrintData(const u_char *, int);

struct appHeader
{
	uint32_t timestamp;
	uint16_t length;

	union
	{
		uint16_t cstFlags;
		uint16_t _: 3, c_flag: 1, s_flag: 1, t_flag: 1, status: 10;
	};

	uint16_t cacheControl;
	uint16_t __;
};

struct sockaddr_in sourceAddress, destAddress;
FILE * outputFile;
int packetsAmount = 0;

int main()
{
	char errorBuffer[50];
	pcap_t * interfaceHandler;	// interfaceHandler of the device that shall be sniffed
	// Open the device for sniffing
	printf("Opening loopback interface for packet sniffing...\n ");
	interfaceHandler = pcap_open_live("lo", 65536, 1, 0, errorBuffer);
	char filterText[] = "proto TCP and dst port 9999 or src port 9999 or dst port 9998 or src port 9998";
	struct bpf_program bpf;	
	bpf_u_int32 net; 
	pcap_compile(interfaceHandler, &bpf, filterText, 0, net);
	pcap_setfilter(interfaceHandler, &bpf);

	if (interfaceHandler == NULL)
	{
		fprintf(stderr, "Couldn't open device %s : %s\n", "lo", errorBuffer);
		exit(1);
	}

	outputFile = fopen("315393702__205439649.txt", "w");
	if (outputFile == NULL)
		printf("Unable to create output file.");
	printf("Capturing ,Please wait");
	pcap_loop(interfaceHandler, -1, packetParse, NULL);

	return 0;
}

void packetParse(u_char *placeHolder, const struct pcap_pkthdr *header, const u_char *buffer)
{
	struct iphdr *ipHeader = (struct iphdr *)(buffer + sizeof(struct ethhdr));
	if (ipHeader->protocol == 6)	//filter should do the work anyway but just in case
		packetPrint(buffer, header);
}

void packetPrint(const u_char *Buffer, const struct pcap_pkthdr *header)
{
	// Network (IP) Layer
	struct iphdr *ipHeader = (struct iphdr *)(Buffer + sizeof(struct ethhdr));
	unsigned short ipHeaderlen = ipHeader->ihl * 4;
	memset(&sourceAddress, 0, sizeof(sourceAddress));
	sourceAddress.sin_addr.s_addr = ipHeader->saddr;
	memset(&destAddress, 0, sizeof(destAddress));
	destAddress.sin_addr.s_addr = ipHeader->daddr;

	// TCP Layer (Transport)
	struct tcphdr *tcpHeader = (struct tcphdr *)(Buffer + ipHeaderlen + sizeof(struct ethhdr));
	u_int tcpHeaderLen = tcpHeader->th_off * 4;

	// Application Layer
	const struct appHeader *appHeader = (struct appHeader *)(Buffer + 14 + ipHeaderlen + tcpHeaderLen);
	packetsAmount++;
	printf("TCP PACKET CAPTURED: %d \n ", packetsAmount);
	fprintf(outputFile, "\n#######-----START-----#######\n");
	fprintf(outputFile, "{source_ip:%s\n", inet_ntoa(sourceAddress.sin_addr));
	fprintf(outputFile, "dest_ip: %s\n", inet_ntoa(destAddress.sin_addr));
	fprintf(outputFile, "source_port: %u\n", ntohs(tcpHeader->source));
	fprintf(outputFile, "dest_port: %u\n", ntohs(tcpHeader->dest));
	fprintf(outputFile, "timestamp : %u\n", ntohl(appHeader->timestamp));
	fprintf(outputFile, "total_length:%u \n", ntohs(appHeader->length));
	fprintf(outputFile, "cache_flag: %u \n", (ntohs(appHeader->cstFlags) >> 12) &1);
	fprintf(outputFile, "steps_flag: %u \n", (ntohs(appHeader->cstFlags) >> 11) &1);
	fprintf(outputFile, "type_flag: %u \n", (htons(appHeader->cstFlags) >> 10) &1);
	fprintf(outputFile, "status_code: %u \n", htons(appHeader->cstFlags) &0x3ff);
	fprintf(outputFile, "cache_control:%u \n", ntohs(appHeader->cacheControl));
	fprintf(outputFile, "data:\n");
	int header_size = sizeof(struct ethhdr) + ipHeaderlen + tcpHeader->doff * 4;
	packetPrintData(Buffer + header_size, header->len - header_size);
	fprintf(outputFile, "}\n");
	fprintf(outputFile, "\n#######-----END-----#######\n");

}

void packetPrintData(const u_char *data, int dataLen)
{
	int i;
	for (i = 0; i < dataLen; i++)
	{
		if (i % 16 == 0)
			fprintf(outputFile, "\n");
		fprintf(outputFile, " %02X", (unsigned int) data[i]);
	}
}