#include <stdint.h>
#include <string>
#include "../exceptions.h"
#include "../util.h"
#include <vector>
#include "networking.h"
#include <errno.h>
#pragma once


namespace tools
{
    namespace networking
    {
        struct TCPPacket
        {
            uint16_t source;
            uint16_t dest;
            uint32_t sequencenumber;
            uint32_t acknumber;
            unsigned char offset;
            unsigned char flags;
            uint16_t window;
            uint16_t checksum;
            uint16_t urgentptr;
            unsigned char *options;
            unsigned char *data;
            uint32_t truesize;
            TCPPacket()
            {
                ;
            }
            ~TCPPacket()
            {
                delete[] this->options;
                delete[] this->data;
            }
            TCPPacket(const TCPPacket &packet)
            {
                memcpy(this, &packet, SIZEOFTCP);
                this->options = new unsigned char[packet.offset - SIZEOFTCP];
                memcpy(this->options, packet.options, packet.offset - SIZEOFTCP);
                this->data = new unsigned char[packet.truesize - packet.offset];
                memcpy(this->data, packet.data, packet.truesize - packet.offset);
            }
            std::string ToString();
        };

        TCPPacket* GetTCP(IPv4Packet* packet);

        class RawIPv4TCPSocket {
            private:
                uint32_t source;
                uint32_t dest;
                uint16_t port;
                unsigned char ttl;
                RawSocket _socket;
            public:
                RawIPv4TCPSocket() {}
                RawIPv4TCPSocket(uint32_t dest, uint16_t port);
                ~RawIPv4TCPSocket() {}
        };

        class IPv4TCPConnection {
            private:
                int _socket;
            public:
                IPv4TCPConnection() {}
                IPv4TCPConnection(int socket) : _socket(socket) {}
                ~IPv4TCPConnection() {}
                void Send(const char *message, int size);
                unsigned char* Receive(int amount);
                void Close();
        };

        class IPv4TCPClientSocket {
            private:
                uint32_t dest;
                uint16_t port;
                unsigned char ttl;
                int _socket;
                sockaddr_in addr;
            public:
                IPv4TCPClientSocket() {}
                IPv4TCPClientSocket(const char* dest, uint16_t port);
                ~IPv4TCPClientSocket() {}
                void Send(const char *message, int size);
                unsigned char* Receive(int amount);
                void Close();
        };

        class IPv4TCPServerSocket {
            private:
                uint32_t source;
                uint16_t port;
                unsigned char ttl;
                int _socket;
                int next;
                sockaddr_in addr;
            public:
                IPv4TCPServerSocket() {}
                IPv4TCPServerSocket(const char* source, uint16_t port);
                ~IPv4TCPServerSocket() {}
                void Listen();
                int AcceptNew();
                void CloseAll();
        };
    }
}