#include "tcp.h"

namespace tools
{
    namespace networking
    {
        TCPPacket* GetTCP(IPv4Packet* packet)
        {
            TCPPacket* ret = new TCPPacket();
            std::memcpy(ret, packet->data, SIZEOFTCP);
            ret->offset = ret->offset >> 4;
            ret->options = new unsigned char[ret->offset - (SIZEOFTCP)];
            std::memcpy(ret->options, packet->data + (SIZEOFTCP), ret->offset - (SIZEOFTCP));
            ret->truesize = packet->truesize - SIZEOFIPV4;
            if (ret->truesize < ret->offset)
            {
                throw tools::exceptions::NetworkSizeMismatch("offset is larger than the size of the data");
            }
            uint16_t remainingsize = ret->truesize - ret->offset;
            ret->options = new unsigned char[remainingsize];
            std::memcpy(ret->data, packet->data + ret->offset, remainingsize - (SIZEOFTCP));
            ret->source = htons(ret->source);
            ret->dest = htons(ret->dest);
            return ret;
        }

        RawIPv4TCPSocket::RawIPv4TCPSocket(uint32_t dest, uint16_t port) {
            this->dest = dest;
            this->port = port;
            this->_socket = RawSocket(GetDefaultInterface());
            EthernetFrame *frame = new EthernetFrame();
            std::memcpy(frame->source, this->_socket.GetMac(), 6);
            std::memcpy(frame->dest, this->_socket.GetMac(), 6);
        }

        unsigned char* IPv4TCPConnection::Receive(int size) {
            unsigned char* buff = new unsigned char[size];
            recv(this->_socket, buff, size, 0);
            return buff;
        }

        void IPv4TCPConnection::Send(const char* message, int size) {
            send(this->_socket, message, size, 0);
        }

        IPv4TCPClientSocket::IPv4TCPClientSocket(const char* dest, uint16_t port) {
            this->_socket = socket(AF_INET, SOCK_STREAM, 0);
            memset(&this->addr, 0, sizeof(this->addr));
            this->addr.sin_family = AF_INET;
            this->addr.sin_port = htons(port);
            if (inet_pton(AF_INET, dest, &this->addr.sin_addr) <= 0) {
                fprintf(stderr, "socket() failed1: %s\n", strerror(errno));
            }
            if (connect(this->_socket, (struct sockaddr*)&this->addr, sizeof(this->addr)) == -1) {
                fprintf(stderr, "socket() failed2: %s\n", strerror(errno));
            }
        }

        void IPv4TCPClientSocket::Close() {
            close(this->_socket);
        }

        void IPv4TCPClientSocket::Send(const char* message, int size) {
            send(this->_socket, message, size, 0);
        }

        IPv4TCPServerSocket::IPv4TCPServerSocket(const char* source, uint16_t port) {
            this->_socket = socket(AF_INET, SOCK_STREAM, 0);
            int opt = 1;
            setsockopt(this->_socket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));
            memset(&this->addr, 0, sizeof(this->addr));
            this->addr.sin_family = AF_INET;
            this->addr.sin_port = htons(port);
            if (strcmp(source, "any") != 0) {
                inet_pton(AF_INET, source, &this->addr.sin_addr);
            } else {
                this->addr.sin_addr.s_addr = htonl(INADDR_ANY);
            }
            if (bind(this->_socket, (struct sockaddr*)&this->addr, sizeof(this->addr)) == -1) {
                fprintf(stderr, "socket() failed: %s\n", strerror(errno));
            }
        }

        void IPv4TCPServerSocket::CloseAll() {
            close(this->_socket);
        }

        void IPv4TCPServerSocket::Listen() {
            listen(this->_socket, 3);
        }

        int IPv4TCPServerSocket::AcceptNew() {
            struct sockaddr_in clientaddr;
            auto size = (unsigned int)sizeof(clientaddr);
            int newsock = accept(this->_socket, (struct sockaddr*)&clientaddr, &size);
            return newsock;
        }
    }
}