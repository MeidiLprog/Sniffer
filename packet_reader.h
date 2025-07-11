#ifndef __PACKET_READER__
#define __PACKET_READER__
#include <iostream>
#include <cstdint>
#include <arpa/inet.h>
using namespace std;

struct Options{
    uint32_t packets_count = 0;
    bool infinite = false;
    string interface = "";
    bool promisc = false;
    bool enable_http = false;
};

void start_sniffing(const Options& opt);


#pragma pack(push,1)

    struct EthernetH{

        uint8_t dst[6];
        uint8_t src[6];
        uint16_t ethertype;

    };
    #pragma pack(pop)



#pragma pack(push,1)
    struct IPV4Header {
    uint8_t version_ihl;          // Byte 0
    uint8_t type_of_service;      // Byte 1
    uint16_t length_mss;          // Bytes 2-3

    uint16_t identification;      // Bytes 4-5
    uint16_t flags_fragment;      // Bytes 6-7

    uint8_t ttl;                  // Byte 8
    uint8_t protocol;             // Byte 9
    uint16_t checksum;            // Bytes 10-11

    uint32_t src_ip;              // Bytes 12-15
    uint32_t dst_ip;              // Bytes 16-19
};
#pragma pack(pop)

#pragma pack(push,1)
    struct TCPHeader{
        uint16_t src_port;
        uint16_t dst_port;
        uint32_t SQN;
        uint32_t ACK_N;
        uint16_t BFORE_WINDOW; // I need to retrieve data offset: reserved: flags
        uint16_t Window;
        uint16_t checksum;
        uint16_t urgent_pointer;
        //I chose not to add options+padding and data, because options may vary, therefore it is unpredictible

    };
#pragma pack(pop)

#pragma pack(push,1)
    struct UDPHeader {
        uint16_t src_port;
        uint16_t dst_port;
        uint16_t length;
        uint16_t checksum;
    };
#pragma pack(pop)


//Even though functions exist to parse and convert binary ip addresses
// I prefered do it myself as I'm only doing ipv4
void calculate_ip(uint32_t ip);

#endif