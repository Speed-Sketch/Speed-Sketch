#ifndef DATASET_BASE_HEADER
#define DATASET_BASE_HEADER

#include <vector>
#include <string>
#include <cstring>
#include <cstdint>
using std::vector;
using std::string;

typedef struct {
    // real information
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    uint8_t protocol;
    uint32_t size;
    double timestamp;
    // abstract information
    uint32_t footprint; // usually be hashed ip&port info
}Packet;


class Dataset {
public:
    vector<Packet> flow;
    uint32_t seed;

    // constructor
    Dataset(uint32_t seed = 0x123) : seed(seed) {}

    // basic func
    int flowsize() const { return flow.size(); }
    double duration() const { return flow.size() ? (flow.back().timestamp - flow.front().timestamp) : 0.; }
    Packet& operator [] (int i) { return flow[i]; }
    void trim(int size) { if (flow.size() > size) flow.resize(size); }
    void merge(const Dataset &D) {
        vector<Packet> newflow;
        newflow.reserve(flowsize() + D.flowsize());
        for (int i = 0, j = 0; i < flowsize() || j < D.flowsize();) {
            if (j == D.flowsize() || (i != flowsize() && flow[i].timestamp < D.flow[j].timestamp))
                newflow.push_back(flow[i]), i++;
            else newflow.push_back(D.flow[j]), j++;
        }
        flow = newflow;
    }

    // virtual func
    void read(string file_name, int size_limit);
};

#endif