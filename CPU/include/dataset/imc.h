#ifndef DATASET_IMC_HEADER
#define DATASET_IMC_HEADER

#include <iostream>
#include <fstream>
#include <dataset/base.h>
#include <utils.h>
#include <murmur3.h>
#include <arpa/inet.h>
#include <climits>

/*
IMC description:

struct Pkt {
  uint32_t footprint;
  uint32_t size
  double timestamp;
};
*/

class IMCDataset : public Dataset {
public:
    IMCDataset(uint32_t t_seed = 0x123) { seed = t_seed; }

    void read(string file_name, int size_limit = INT_MAX) {
        ifstream is(file_name.c_str(), ios::in | ios::binary);
        char buf[2000] = {0};

        for (int i = 0; i < size_limit; i++) {
            if(!is.read(buf, 16)) {
                break;
            }
            Packet pkt;
            pkt.footprint = *((uint32_t*)(buf));
            pkt.size = *((uint32_t*)(buf+4));
            pkt.timestamp = *((double*)(buf+8));
            pkt.timestamp /= 1000;
            flow.push_back(pkt);
        }
        cout << "Loading complete. flow_size: " << flow.size() << endl;
    }
};

#endif