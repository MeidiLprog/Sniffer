#include <iostream>
#include <cstring>
#include <cstdlib>
#include "packet_reader.h"



using namespace std;



void helper(void){

    cout << "Usage: ./sniffer [Options]\n"
         << "Options \n"
         << " --help              Bring up the manual\n"
         << " --count N           Set the number of packets you want to capture\n" 
         << " --infinite          Just like in wireshark it never stops capturing advice use CTRL+C\n" 
         << " --interface <name>  choose which interface to listen to\n"
         << " --promisc           Activate promisc on your interface\n"
         << " --http              Activate http parsing"
         << endl;
    exit(0);
}



Options parse_arg(int argc,char**argv){
    Options opt;

    for(int i = 0; i < argc; ++i){

        if(strcmp(argv[i],"--help") == 0){
            helper();
        }
        else if(strcmp(argv[i],"--count") == 0 && i+1 < argc){
            opt.packets_count = atoi(argv[++i]);
           //cout << "packet number set " << opt.packets_count << endl; debug
        }
        else if(strcmp(argv[i], "--infinite") == 0) {
            opt.infinite = true;
        }
        else if(strcmp(argv[i], "--interface") == 0 && i + 1 < argc) {
            opt.interface = argv[++i];
        }
        else if(strcmp(argv[i], "--promisc") == 0) {
            opt.promisc = true;
        }
        else if(strcmp(argv[i], "--http") == 0) {
            opt.enable_http = true;
        }

    }

    return opt;

}





int main(int argc,char**argv){
    Options opt = parse_arg(argc,argv);

    cout << "Configuration:" << endl;
    cout << " Packets count: " << opt.packets_count << endl;
    cout << " Infinite: " << (opt.infinite ? "yes" : "no") << endl;
    cout << " Interface: " << opt.interface << endl;
    cout << " Promisc: " << (opt.promisc ? "yes" : "no") << endl;
    cout << " HTTP enabled: " << (opt.enable_http ? "yes" : "no") << endl;


    start_sniffing(opt);

    return 0;

}