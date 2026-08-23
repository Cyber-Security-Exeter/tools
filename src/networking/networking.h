#include <stdint.h>
#include <string>
#include "../exceptions.h"
#include "../util.h"
#include "../io.h"
#include <vector>
#ifdef __linux__
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#elif _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <pcap.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>
#pragma comment(lib, "Ws2_32.lib")
#endif
#pragma once

#define ETHER_TYPE_IPv4 0x0800 /**< IPv4 Protocol. */
#define ETHER_TYPE_IPv6 0x86DD /**< IPv6 Protocol. */
#define ETHER_TYPE_ARP 0x0806  /**< Arp Protocol. */
#define ETHER_TYPE_RARP 0x8035 /**< Reverse Arp Protocol. */
#define ETHER_TYPE_VLAN 0x8100 /**< IEEE 802.1Q VLAN tagging. */
#define ETHER_TYPE_1588 0x88F7 /**< IEEE 802.1AS 1588 Precise Time Protocol. */
#define ETHER_TYPE_SLOW 0x8809 /**< Slow protocols (LACP and Marker). */
#define ETHER_TYPE_TEB 0x6558  /**< Transparent Ethernet Bridging. */

#define SIZEOFETH 14
#define SIZEOFIPV4 24
#define SIZEOFTCP 20
#define SIZEOFICMP 8

#define LOCALDEFAULT (uint32_t)0x7f000001
#define RESERVED1 (uint32_t)0x00000000
#define RESERVED1RANGE 8
#define RESERVED2 (uint32_t)0xa9fe0000
#define RESERVED2RANGE 16
#define RESERVED3 (uint32_t)0xf0000000
#define RESERVED3RANGE 4

#define NONE -1
#define ETH 0
#define IPV4 1
#define TCP 2
#define ICMP 3

#ifdef _WIN32

inline int init()
{
    WSADATA wsaData;
    int iResult;

    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0)
    {
        printf("WSAStartup failed: %d\n", iResult);
        return 1;
    }
    return 0;
}

inline int intialised = init();

#endif

namespace tools
{
    namespace networking
    {

        struct ICMPPacket
        {
            unsigned char type;
            unsigned char code;
            uint16_t checksum;
            uint32_t extendedheader;
            unsigned char* data;
            uint32_t size;
            ICMPPacket()
            {
                ;
            }
            ~ICMPPacket()
            {
                delete[] this->data;
            }
            ICMPPacket(const ICMPPacket &packet)
            {
                memcpy(this, &packet, SIZEOFICMP);
                this->data = new unsigned char[packet.size - SIZEOFICMP];
                memcpy(this->data, packet.data, packet.size - SIZEOFICMP);
            }
            std::string ToString();
        };

        struct IPv4Packet
        {
            unsigned char vihl;
            unsigned char tos;
            uint16_t length;
            unsigned char identification[2];
            uint16_t flagfrag;
            unsigned char ttl;
            unsigned char protocol;
            unsigned char checksum[2];
            uint32_t source;
            uint32_t dest;
            unsigned char options[40];
            unsigned char *data;
            uint32_t truesize;
            IPv4Packet()
            {
                ;
            }
            ~IPv4Packet()
            {
                delete[] this->data;
            }
            IPv4Packet(const IPv4Packet &packet)
            {
                memcpy(this, &packet, SIZEOFIPV4);
                this->data = new unsigned char[packet.length - SIZEOFIPV4];
                memcpy(this->data, packet.data, packet.length - SIZEOFIPV4);
            }
            std::string ToString();
        };

        struct EthernetFrame
        {
            unsigned char dest[6];
            unsigned char source[6];
            unsigned char lengthtype[2];
            unsigned char *data;
            uint32_t truesize;
            EthernetFrame()
            {
                ;
            }
            ~EthernetFrame()
            {
                delete[] this->data;
            }
            EthernetFrame(const EthernetFrame &packet)
            {
                memcpy(this, &packet, SIZEOFIPV4);
                this->data = new unsigned char[packet.truesize - SIZEOFIPV4];
                memcpy(this->data, packet.data, packet.truesize - SIZEOFIPV4);
            }
            void ParseVec(const std::vector<unsigned char> frame);
            IPv4Packet GetIPv4() const;
            std::string ToString();
        };

        class RawSocket
        {
        private:
            char mac[6];
#ifdef __linux__
            int32_t fd;
#elif _WIN32
            pcap_t *handle;
#endif

        public:
            RawSocket();
            RawSocket(const std::string &_interface);
            ~RawSocket();
            std::vector<unsigned char> ReceivePacketRaw();
            EthernetFrame ReceivePacket();
            void SendPacketRaw(const std::vector<unsigned char> &packet);
            void SendPacket(const EthernetFrame &eth);
            const char* GetMac() {return this->mac;}
        };

        std::string GetDefaultInterface();

        unsigned char* GetDeviceMac(std::string interface);
    }
}