#ifndef DATASET_CAIDA_HEADER
#define DATASET_CAIDA_HEADER

#include <iostream>
#include <fstream>
#include <dataset/base.h>
#include <utils.h>
#include <murmur3.h>
#include <arpa/inet.h>
#include <climits>

/*
CAIDA18 description:

struct Pkt {
  uint32_t srcip;
  uint16_t srcpt;
  uint32_t dstip;
  uint16_t dstpt;
  uint8_t protocol;
  uint16_t length;
  double timestamp;
};
*/

class CAIDA18 : public Dataset {
public:
    CAIDA18(uint32_t t_seed = 0x123) { seed = t_seed; }

    void read(string file_name, int size_limit = INT_MAX) {
        ifstream is(file_name.c_str(), ios::in | ios::binary);
        char buf[2000] = {0};

        for (int i = 0; i < size_limit; i++) {
            if(!is.read(buf, 23)) {
                break;
            }
            Packet pkt;
            pkt.src_ip = ntohl(*((uint32_t*)buf));
            pkt.dst_ip = ntohl(*((uint32_t*)(buf+4)));
            pkt.src_port = ntohs(*((uint16_t*)(buf+8)));
            pkt.dst_port = ntohs(*((uint16_t*)(buf+10)));
            pkt.protocol = *((uint8_t*)(buf+12));
            pkt.size = ntohs(*((uint16_t*)(buf+13)));
            pkt.timestamp = *((double*)(buf+15));
            // ip + port + protocol
            pkt.footprint = MurmurHash3_x86_32((void*)buf, 13, seed);
            flow.push_back(pkt);
        }
        cout << "Loading complete. flow_size: " << flow.size() << endl;
    }
};

#endif