#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/types.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/stat.h>
// IPv4 header len without options
#define IP4_HDRLEN 20

// ICMP header len for echo req
#define ICMP_HDRLEN 8

#define SIZE_OF_PACKET 60

// Compute checksum (RFC 1071).
unsigned short calculate_checksum(unsigned short *paddress, int len)
{
    int nleft = len;
    int sum = 0;
    unsigned short *w = paddress;
    unsigned short answer = 0;

    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1)
    {
        *((unsigned char *)&answer) = *((unsigned char *)w);
        sum += answer;
    }

    // add back carry outs from top 16 bits to low 16 bits
    sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
    sum += (sum >> 16);                 // add carry
    answer = ~sum;                      // truncate to 16 bits

    return answer;
}

// Fill the ICMP header
// length - the length of the ICMP payload
void setICMPHeader(struct icmp *header)
{
	//Set type to Echo Reply
	header->icmp_type = ICMP_ECHOREPLY;
	//Code 0 for reply:
	header->icmp_code = 0;
	//ID. random number
	header->icmp_id = htons(50179);
	//Icmp sequence number use htons to transform big endian:
	header->icmp_seq = 0;
	/*We set the checksum value to zero before passing the packet
	into the checksum function. Note that this checksum is 
	calculate over the ICMP header only. Upper layer protocols 
	have their own checksum fields, and must be calculated seperately.*/
	header->icmp_cksum = 0;
	char packet[] = "Echo reply";
	memcpy(header + ICMP_HDRLEN, packet, strlen(packet) + 1);
	header->icmp_cksum = calculate_checksum((unsigned short *)(header), ICMP_HDRLEN + strlen(packet) + 1);
}

//Fill the IP header
void setIPheader(struct ip *header, const uint32_t src, const uint32_t dest)
{
	printf("Set IP header\n");
	/*printf("From: %u\n", src);
	printf("To: %u\n", dest);*/
	header->ip_hl = 0x5;
	//Protocol Version is 4, meaning Ipv4:
	header->ip_v = 0x4;
	//Type of Service. Packet precedence:
	header->ip_tos = 0x0;
	/*Total length for our packet require to be converted to the network
	byte-order(htons(60), but MAC OS doesn't need this):*/
	header->ip_len = 60;
	//ID field uniquely identifies each datagram sent by this host:
	header->ip_id = 0;
	/*Fragment offset for our packet. 
	We set this to 0x0 since we don't desire any fragmentation:*/
	header->ip_off = 0x0;
	/*Time to live. 
	Maximum number of hops that the packet can 
	pass while travelling through its destination.*/
	header->ip_ttl = 64;
	//Upper layer (Layer III) protocol number:
	header->ip_p = IPPROTO_ICMP;
	/*We set the checksum value to zero before passing the packet
	into the checksum function. Note that this checksum is 
	calculate over the IP header only. Upper layer protocols 
	have their own checksum fields, and must be calculated seperately.*/
	header->ip_sum = 0x0;
	/*Source IP address, this might well be any IP address that 
	may or may NOT be one of the assigned address to one of our interfaces:*/
	//header->ip_src.s_addr = inet_addr(src);
	header->ip_src.s_addr = src;
	//  Destination IP address:
	//header->ip_dst.s_addr = inet_addr(dest);
	header->ip_dst.s_addr = dest;
	// calaukate checksum:
	header->ip_sum = calculate_checksum((unsigned short *)(header), sizeof(*header));
}

void gotPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	//received fields:
	int packet_length = header->len, sd;
	const int on = 1;
	struct ether_header *Reth = (struct ether_header *) packet;
	struct iphdr *Rip = (struct iphdr *) (packet + sizeof(struct ether_header));
	struct icmphdr *Ricmp = (struct icmphdr *) (packet + sizeof(struct ether_header) + sizeof(struct iphdr));
	if (Ricmp->type == ICMP_ECHOREPLY)
	{
		printf("got responde");
		return;
	}
	printf("\n**Received a packet**\n");
	printf("  From: %s\n", inet_ntoa(*(struct in_addr *) &Rip->saddr));
	printf("  To: %s\n", inet_ntoa(*(struct in_addr *) &Rip->daddr));
	printf("\nCreating a respond ICMP packet\n");

	//fields for the reply. in order to spoof we need to chande the ip src in the packet we send back
	struct ip ip;
	struct icmp icmp;
	struct sockaddr_in sin;
	memset(&ip, 0, sizeof(ip));
	memset(&icmp, 0, sizeof(icmp));
	memset(&sin, 0, sizeof(sin));

	u_char* replyPacket=  (u_char *)malloc(SIZE_OF_PACKET);
	memset(replyPacket, 0, SIZE_OF_PACKET);
	//set and append the ip header:
	const char *newSrc = inet_ntoa(*(struct in_addr *) &Rip->daddr);
	const char *newDest = inet_ntoa(*(struct in_addr *) &Rip->saddr);
	/*printf("src: %s\n", newSrc);
	printf("dest: %s\n", newDest);*/
	//setIPheader(&ip, newSrc, newDest);
	setIPheader(&ip, Rip->daddr, Rip->saddr);
	memcpy(replyPacket, &ip, IP4_HDRLEN);
	//set and append the ICMP header:
	setICMPHeader(&icmp);
	/*printf("newSrc: %u", ip.ip_src);
	printf("newDst: %u", ip.ip_dst);*/
	memcmp(replyPacket + IP4_HDRLEN, &icmp, ICMP_HDRLEN);

	printf("\nIP and ICMP headres appended\n");

	//create raw socket:
	sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sd < 0)
	{
		perror("raw socket");
		exit(1);
	}

	//set the ip header to be the one we created:
	if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
	{
		perror("setsockopt");
		exit(1);
	}
	
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = ip.ip_dst.s_addr;

	//send the packet:
	if(sendto(sd, replyPacket, SIZE_OF_PACKET, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr)) < 0)
	{
		perror("sendto");
		exit(1);
	}
	printf("**Package sent back**\n");
	close(sd);
}

int main()
{
    pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filterExp[] = "icmp";
	bpf_u_int32 net;
	bpf_u_int32 mask;
	pcap_if_t *devices;

	// Set a device
	if (pcap_findalldevs(&devices, errbuf) != 0)
	{
		printf("pcap_findalldevs failed: %s\n", errbuf);
		return(2);
	}

	//char *dev = devices->name;
	char dev[] = "enp0s3";
	/*pcap_if_t *temp = devices;
	while (temp != NULL)
	{
		printf("name: %s, des: %s\n", temp->name, temp->description);
		temp = temp->next;
	}*/

	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) 
	{
		printf("Can't get netmask for device %s\n", dev);
		net = 0;
		mask = 0;
	}

    // Open "dev" for sniffing
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL)
	{
		printf("Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}

	// "Compile" and set the filter
	if (pcap_compile(handle, &fp, filterExp, 0, net) == -1)
	{
		printf("Couldn't parse filter %s: %s\n", filterExp, pcap_geterr(handle));
		return(2);
	}

	if (pcap_setfilter(handle, &fp) == -1)
	{
		printf("Couldn't install filter %s: %s\n", filterExp, pcap_geterr(handle));
		return(2);
	}
	
	// Start the sniffing loop
	printf("staet sniffing on device: %s, with filter: %s\n", dev, filterExp);
	pcap_loop(handle, -1, gotPacket, NULL);

	pcap_close(handle); //Close the handle
	return 0;
}