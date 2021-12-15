#include <cstdio>
#include <ifaddrs.h>
#include <pcap.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string>
#include <map>
#include "airodump.h"

using namespace std;

map<string, pair<int, string>> table;

char *dev;
char errbuf[PCAP_ERRBUF_SIZE];
pcap_t *handle;
struct pcap_pkthdr *header;
const u_char *packet;

void usage()
{
	printf("syntax: airodump <interface>\n");
	printf("sample: airodump mon0\n");
}

int main(int argc, char* argv[])
{
	if (argc != 2) {
		usage();
		return -1;
	}
	
	dev = argv[1];
	handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	
	while(true) {
		int res = pcap_next_ex(handle, &header, &packet);
		if(res == 0)continue;
		if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}
		
		radiotap_header *rt = (struct radiotap_header *)packet;
		beacon_header *bc = (struct beacon_header *)(packet + rt -> it_len);
		/*printf("%p %d\n",bc,sizeof(beacon_header));
		bc->print();
		for(int i = 0; i < sizeof(bc); i++){
			printf("%02x ", *(char*)(bc + i));
		}*/
		
		if(bc -> type != 0x80) continue;
		string bssid = string(bc -> bssid);
		beacon_fixed *bf = (struct beacon_fixed *)(packet + rt -> it_len + sizeof(beacon_header));
		beacon_ssid *bs = (struct beacon_ssid *)(packet + rt -> it_len + sizeof(beacon_header) + sizeof(beacon_fixed));
		
		if(table.find(bssid) != table.end()) {
			string essid = string(bs -> essid, bs -> len);
			table[bssid] = {1, essid};
		}
		else table[bssid].first++;
		
		system("clear");
		printf("BSSID\t\t\tBEACONS\tESSID\n");
		for(auto k : table) {
			printf("%s\t%d\t%s\n", k.first.c_str(), k.second.first, k.second.second.c_str());
		}
	}

	pcap_close(handle);
}
