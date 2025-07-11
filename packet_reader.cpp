    #include <iostream>
    #include <stdbool.h>
    #include <cstdint>
    #include <cstring>

    #include <sys/socket.h>
    #include <linux/if_packet.h>
    #include <net/ethernet.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <stddef.h>

    #include <vector>
    #include <cassert>

    #include <net/if.h>
    #include <sys/ioctl.h>

    #include "packet_reader.h"

    using namespace std;

void display_ascii(const uint8_t* p, size_t len) {
    if (len == 0) return;

    for (size_t i = 0; i < len; i += 16) {
        // Offset
        printf("%04zx  ", i);

        // Hex bytes
        for (size_t j = 0; j < 16; ++j) {
            if (i + j < len)
                printf("%02x ", p[i + j]);
            else
                printf("   "); 
            if (j == 7) printf(" "); 
        }

        printf(" ");

        // ASCII representation
        for (size_t j = 0; j < 16 && (i + j) < len; ++j) {
            char c = p[i + j];
            printf("%c", isprint(c) ? c : '.');
        }

        printf("\n");
    }
}

// TCP FUNCTIONS TO CHECK + PARSE
bool is_http(const uint8_t* p, size_t len) {
    if (len < 4) return false;

    return (strncmp(reinterpret_cast<const char*>(p), "GET ", 4) == 0 ||
            strncmp(reinterpret_cast<const char*>(p), "POST", 4) == 0 ||
            strncmp(reinterpret_cast<const char*>(p), "HEAD", 4) == 0 ||
            strncmp(reinterpret_cast<const char*>(p), "HTTP", 4) == 0);
}

void parse_http(uint8_t*p, size_t len){
    cout << "=== HTTP detected ===" << endl;
    for(size_t i = 0; i < len ; ++i){
        char c = static_cast<char>(p[i]);
        if(isprint(c) || c == '\r' || c == '\n')
            cout << c;
        cout << ".";


    }




    cout << "=== END PARSING HTTP ===" << endl;




}





void calculate_ip(uint32_t ip){
    ip = ntohl(ip);  // conversion ici
    cout << "IP: "
         << static_cast<int>((ip >> 24) & 0xFF) << "."
         << static_cast<int>((ip >> 16) & 0xFF) << "."
         << static_cast<int>((ip >> 8) & 0xFF) << "."
         << static_cast<int>(ip & 0xFF)
         << endl;
}



// TCP FUNCTIONS

    //Since all of this is an initiation to low level programming, I try to verify as much as I can
    void verif_structPadding(void) {
        struct EthernetH x;

        cout << "==========Struct=======" << endl;
        cout << "Informations regarding memory alignment thanks to pragma" << endl;
        cout << "offsets of EthernetH + pragma" << endl;
        cout << "dst offset: " << offsetof(EthernetH, dst) << endl;
        cout << "src offset: " << offsetof(EthernetH, src) << endl;
        cout << "ethertype offset: " << offsetof(EthernetH, ethertype) << endl;
        cout << "struct size: " << sizeof(x) << endl;
        cout << "=======END=====" << endl;
    }

    void info_ether(struct EthernetH* p){

        cout << "=======INfo ethernet header===" << endl;
        cout << "Source MAC: " << "\t";
        for(uint8_t i = 0; i <= 5; ++i){

            cout << std::hex << static_cast<int>(p->src[i]);
            if(i!=5) cout <<":";
        }
        cout << endl;
        cout << "Dest MAC: " << "\t";
        for(uint8_t i = 0; i <= 5; ++i){

            cout << std::hex <<static_cast<int>(p->dst[i]);
            if(i!=5) cout <<":";
        }
        cout << endl;

        cout << "Protocol of packet in hex 0x" << std::hex << ntohs(p->ethertype) << std::dec << endl;  
        return;
    }

        void info_ipv4(struct IPV4Header* p){
            //version indicates ipv4,ipv6 and the value sought are either 4 or 6
            uint8_t version = p->version_ihl >> 4; // MSB 
            uint8_t ihl = (p->version_ihl & 0x0F) *4; // LSB + multiply by for to get real size
            uint16_t length_mss = ntohs(p->length_mss);

            uint16_t identification = ntohs(p->identification);
            
            uint16_t unparsed_flag = ntohs(p->flags_fragment);
            uint8_t flags = (unparsed_flag >> 13) & 0x07; // I keep the 3 flags DM,
            uint16_t fragment_offeset = unparsed_flag & 0x1FFF; // now I have retried the fragment offeset
            // ex DF MF 0, DF -> don't frag, MF more frag, 0 reserved
            uint8_t ttl = p->ttl;
            uint8_t protocol = p->protocol; // tcp 6,udp 17, icmp 1 etc
            uint16_t checksum = ntohs(p->checksum);
            
            uint32_t src_ip = p->src_ip;
            uint32_t dst_ip = p->dst_ip;


            cout << "======= Info IP Header =======" << std::endl;
                cout << "Version: " << static_cast<int>(version) << std::endl;
                cout << "Header Length: " << static_cast<int>(ihl) << " bytes" << std::endl;
                cout << "Total Length: " << length_mss << std::endl;
                cout << "Identification: " << identification << std::endl;
                cout << "Flags: 0x" << std::hex << static_cast<int>(flags) << std::dec << std::endl;
                cout << "Fragment Offset: " << fragment_offeset << std::endl;
                cout << "TTL: " << static_cast<int>(ttl) << std::endl;

                string proto_name;
                switch (protocol) {
                    case 1: proto_name = "ICMP"; break;
                    case 6: proto_name = "TCP"; break;
                    case 17: proto_name = "UDP"; break;
                    default: proto_name = "Unknown"; break;
                }
                cout << "Protocol: " << proto_name << std::endl;
                cout << "Checksum: 0x" << std::hex << checksum << std::dec << std::endl;

                cout << "Source ";
                calculate_ip(src_ip);
                cout << "Destination ";
                calculate_ip(dst_ip);
            std::cout << "==== END Info IP Header ===" << std::endl;

        }

        void info_tcp(struct TCPHeader*p){
            uint16_t src_port = ntohs(p->src_port);
            uint16_t dst_port = ntohs(p->dst_port);
            uint32_t SQN = ntohl(p->SQN);
            uint32_t ACK_N = ntohl(p->ACK_N);
            uint16_t BFORE_WINDOW = ntohs(p->BFORE_WINDOW); // I need to retrieve data offset: reserved: flags
            
            uint8_t data_offset = (BFORE_WINDOW >> 12) & 0x0F;
            uint8_t reserved = (BFORE_WINDOW >> 9) & 0x07;
            uint8_t nounce_flag = (BFORE_WINDOW >> 8) & 0x01;
            uint8_t FLAGS = BFORE_WINDOW & 0xFF; // 8 bits because of the NC nounce as well CWR ECE URG ACK ETC  
            

            uint16_t Window = ntohs(p->Window);
            uint16_t checksum = ntohs(p->checksum);
            uint16_t urgent_pointer = ntohs(p->urgent_pointer);
            

            cout << "===== TCP Header ====" << endl;
            cout << "Source Port: " << src_port << endl;
            cout << "Destination Port: " << dst_port << endl;
            cout << "Sequence Number: " << SQN << endl;
            cout << "Acknowledgment Number: " <<ACK_N << endl;
            cout << "Data Offset: " << static_cast<int>(data_offset * 4) << " bytes" << endl;
            cout << "Reserved: " << static_cast<int>(reserved) << endl;
            cout << "NS Flag: " << static_cast<int>(nounce_flag) << endl;
            
            vector<string> flag_names; //a vector here is used to get the flags and produce a clean output
            if (FLAGS & 0x01) flag_names.push_back("FIN");
            if (FLAGS & 0x02) flag_names.push_back("SYN");
            if (FLAGS & 0x04) flag_names.push_back("RST");
            if (FLAGS & 0x08) flag_names.push_back("PSH");
            if (FLAGS & 0x10) flag_names.push_back("ACK");
            if (FLAGS & 0x20) flag_names.push_back("URG");
            if (FLAGS & 0x40) flag_names.push_back("ECE");
            if (FLAGS & 0x80) flag_names.push_back("CWR");

            cout << "Flags: ";
            for (size_t i = 0; i < flag_names.size(); ++i) {
                if (i > 0) cout << " ";
                cout << flag_names[i];
            }
            cout << endl;

            cout << "Window: " << Window << endl;
            cout << "Checksum: 0x" << hex << checksum << dec << endl;
            cout << "Urgent Pointer: " << urgent_pointer << endl;
            cout << "=== END TCP Header ===" << endl;


        }

    void info_udp(UDPHeader* p) {
    uint16_t src_port = ntohs(p->src_port);
    uint16_t dst_port = ntohs(p->dst_port);
    uint16_t len = ntohs(p->length);
    uint16_t chksum = ntohs(p->checksum);

    cout << "===== UDP Header ====" << endl;
    cout << "Source Port: " << src_port << endl;
    cout << "Destination Port: " << dst_port << endl;
    cout << "Length: " << len << " bytes" << endl;
    cout << "Checksum: 0x" << hex << chksum << dec << endl;
    cout << "=== END UDP Header ===" << endl;
}


void start_sniffing(const Options& opt) {


        int sock = socket(AF_PACKET,SOCK_RAW,htons(0x0003));//ETH_P_ALL meaning all protocol
        if(sock == -1){
            cerr << "socket couldn't be opened" << endl;
            close(sock);
            return;
        }
        

        //socket opened

        //buffer to read data
        //I use vectors as I do not need to free the memory myself and they are convenient as elements can be inserted at the end
        vector<uint8_t> BUFFER(65535);
        memset(BUFFER.data(),0,BUFFER.size());
        //reading

        ssize_t len;

        //verif the padding
        verif_structPadding();


        //Started to read, now proceed to a loop to retrieve our data
        uint8_t count = 0;
        uint8_t count_ip_packet = 0;
        

        //setting the s
        if (!opt.interface.empty()) {
    struct ifreq ifr {};
    strncpy(ifr.ifr_name, opt.interface.c_str(), IFNAMSIZ - 1);

    // 2. Activation du mode promiscuous si demandé
    if (opt.promisc) {
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == -1) {
            perror("ioctl(SIOCGIFFLAGS)");
        } else {
            ifr.ifr_flags |= IFF_PROMISC;
            if (ioctl(sock, SIOCSIFFLAGS, &ifr) == -1) {
                perror("ioctl(SIOCSIFFLAGS)");
            } else {
                cout << "[INFO] Promiscuous mode enabled on " << opt.interface << endl;
            }
        }
    }

    // 3. Bind to the selected interface
    struct sockaddr_ll sll {};
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = if_nametoindex(opt.interface.c_str());

    if (sll.sll_ifindex == 0) {
        cerr << "[ERROR] Failed to get interface index for " << opt.interface << endl;
        close(sock);
        return;
    }

    if (bind(sock, (struct sockaddr*)&sll, sizeof(sll)) == -1) {
        perror("[ERROR] bind()");
        close(sock);
        return;
    }

    cout << "[INFO] Bound to interface: " << opt.interface << endl;
}




        while(opt.infinite || count < opt.packets_count){

            len = recvfrom(sock,BUFFER.data(),BUFFER.size(),0,nullptr,nullptr);
            if(len < static_cast<ssize_t>(sizeof(EthernetH))) continue;
            
            assert(reinterpret_cast<uintptr_t>(BUFFER.data()) % alignof(EthernetH) == 0);
            EthernetH* parse_eth = reinterpret_cast<EthernetH*>(BUFFER.data());//casting made possible thanks to the pragma and memory alignment 
            //we make a first test and check the ethertype to check what protocol will come up
            if (ntohs(parse_eth->ethertype) != 0x800) {
            // cout << "[INFO] Ignored Ethertype: 0x" << hex << ntohs(parse_eth->ethertype) << dec << endl;
            continue;
        }
            cout << endl;// only IPv4 the rest is ignored as I haven't implemented ipv6
            
            cout << "Protocol: 0x800 (IPv4)" << endl; // check if protocol is ipv4 because 0x800 -> ipv4
            
            ++count;
            // Information ethernetHeader
            info_ether(parse_eth);
                //IP
            if (ntohs(parse_eth->ethertype) == 0x800) {
                ++count_ip_packet;

                if (len < static_cast<ssize_t>(sizeof(EthernetH) + sizeof(IPV4Header)) ) {
                    cerr << "Truncated IPv4 packet, skipping\n";
                    continue;
                }
                // here I'm farther than the ethernet Header therefore I use the pointer
                // of my buffer + the sizeof the struct EthernetHeader as an offset to access the IP Header
            assert(reinterpret_cast<uintptr_t>(BUFFER.data() + sizeof(EthernetH)) % alignof(IPV4Header) == 0);
            IPV4Header* ip = reinterpret_cast<IPV4Header*>(BUFFER.data() + sizeof(EthernetH));
            info_ipv4(ip);
            //TCP HEADER
            
            
            switch (ip->protocol)
            {
            case 6: { // TCP
                uint8_t* offset_to_tcp = BUFFER.data() + sizeof(EthernetH) + ((ip->version_ihl & 0x0F) *4); // base address + struct ethernet + ip_len-ihl
                assert(reinterpret_cast<uintptr_t>(offset_to_tcp) % alignof(TCPHeader) == 0); // check whether we can access our data
                // it's a double check, even if pragma force an alignment of 1 byte, we never know
                
                TCPHeader* tc_p = reinterpret_cast<TCPHeader*>(offset_to_tcp);
                info_tcp(tc_p);
                //calulations to point to the payload
                uint8_t data_offset = (ntohs(tc_p->BFORE_WINDOW) >> 12) & 0x0F;
                uint8_t tcp_header_len = data_offset * 4;

                uint8_t ip_header_len = (ip->version_ihl & 0x0F) * 4;

                //here total_len is total of 2-4 [ETHERNET HEADER][IP HEADER][TCP HEADER][PAYLOAD] 
                uint16_t total_len = ntohs(ip->length_mss);

                
                uint16_t payload_len = total_len - ip_header_len - tcp_header_len;
                // [PAYLOAD] = [PAYLOAD] - [IP HEADER] - [TCP HEADER]

                uint8_t* payload_ptr = BUFFER.data() + sizeof(EthernetH) + ip_header_len + tcp_header_len;


               
                cout << "===== TCP Payload (" << payload_len << " bytes) ====" << endl;
                  display_ascii(payload_ptr,payload_len);
                  if (opt.enable_http && (tc_p->dst_port == htons(80) || tc_p->src_port == htons(80))){

                    if(is_http(payload_ptr,payload_len)) parse_http(payload_ptr,payload_len);

                  }
               
                cout << "=== END TCP Payload ===" << endl;
                 cout << endl;
                break;
            }
            case 17: { // UDP
            uint8_t* offset_to_udp = BUFFER.data() + sizeof(EthernetH) + ((ip->version_ihl & 0x0F) *4);
            assert(reinterpret_cast<uintptr_t>(offset_to_udp) % alignof(UDPHeader) == 0);
            UDPHeader* udp = reinterpret_cast<UDPHeader*>(offset_to_udp);
            info_udp(udp);
            
           
            uint8_t udp_lenght = ntohs(udp->length);


            uint8_t payload_length = udp_lenght - sizeof(UDPHeader);
            uint8_t* payload_ptr = offset_to_udp + sizeof(UDPHeader);

          cout << "===== UDP Payload (" << dec << payload_length << " bytes) ====" << endl;

            display_ascii(payload_ptr,payload_length);
            cout << endl;
            cout << "=== END UDP Payload ===" << endl;
            break;
        }
            default: cout << "unknown protocol" << static_cast<int>(ip->protocol) << endl; break;
            }
            
        
        }

            


        }

        cout << "Number of ip packets: " << static_cast<int>(count_ip_packet) << endl;
        
    


        //we close socket
        close(sock);

        return;
    }

