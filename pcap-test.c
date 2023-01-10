#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PACKET_LENGTH 512

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

struct airodump {
	char BSSID[256];
	int beacons;
	char ESSID[256];
};

struct radiotap_header {
	u_int8_t version;
	u_int8_t pad;
	u_int16_t length;
	u_int32_t present;
} __attribute__((__packed__));


void print_airodump( struct airodump* str_airo, int size)
{
	int i =0;
	printf("\e[1;1H\e[2J");
	printf("%s\t\t\t%s\t%s\n\n","BSSID","beacons","ESSID");
	for(i = 0;i < size; i++)
	{
		printf("%s\t%d\t%s\n", str_airo[i].BSSID, str_airo[i].beacons + 1, str_airo[i].ESSID);
	}
	printf("======================================\n");
}




int main(int argc, char* argv[]) {
	int i;
	struct radiotap_header * radiohdr;
	struct airodump str_airo[32];
	int scaned_beacon = 0;
	char BSSID[19];
	printf("code start \n");
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		u_int8_t *temp_pointer;
		int tag_length = 0;
		int res = pcap_next_ex(pcap, &header, &packet);
		int flag = 0;
		u_int8_t subtype = 0;
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		print_airodump(str_airo,scaned_beacon);
		/*
		for( i = 0; i < 24; i++){
			printf("%02x ",packet[i]);
			if(i % 8 == 7)
				printf("\n");
		}
		*/
		// check packet header length
		radiohdr = packet;
		//printf("radio_heder_length : %02d\n",radiohdr->length);
		
		// check Beacon Frame
		temp_pointer = packet + radiohdr->length;
		//printf("Subtype : %x\n",temp_pointer[0]);
		subtype = temp_pointer[0];
		if( subtype != 0x80)
			continue;
		// print BSSID
		temp_pointer += 0x10;
		sprintf(BSSID,"%02x:%02x:%02x:%02x:%02x:%02x",temp_pointer[0],temp_pointer[1],temp_pointer[2],temp_pointer[3],temp_pointer[4],temp_pointer[5]);
		//printf("BSSID : %s\n",BSSID);
		
		for(i =0; i < scaned_beacon; i++)
		{
			if(!strcmp(str_airo[i].BSSID, BSSID))
			{
				str_airo[i].beacons++;
				flag = 1;
			}
		}
		if(flag){
			//printf("flag : %d\n",flag);
			continue;
		}


		strcpy(str_airo[scaned_beacon].BSSID,BSSID);
		// check tag_length
		temp_pointer += 0x15;
		tag_length = temp_pointer[0];
		//printf("Tag length : %d\n",tag_length);
		
		// print ESSID
		if( tag_length != 0) {
			char * essid = (char *)calloc(1,tag_length + 1);
			memcpy(essid, temp_pointer + 1, tag_length);
			//essid[tag_length] = 0;
			//printf("ESSID : %s\n",essid);
			strcpy(str_airo[scaned_beacon].ESSID,essid);
			free(essid);
		}
		scaned_beacon++;
		//printf("%u bytes captured\n", header->caplen);
	}

	pcap_close(pcap);
}

