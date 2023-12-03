#ifndef IMPL_HEADER
#define IMPL_HEADER

#include <iostream>
#include <vector>
#include <cstring>
#include <cstdint>
using std::vector;
using std::pair;
using std::max;
using std::min;

typedef pair<int, int> PII;
#define mp std::make_pair
#define ft first
#define sc second

typedef enum {
    NOP, OP
}Signal;

class Solution {
public:
    char name[100];
    double mem;
    // bucket size
    uint32_t B;
    // token incr speed * microsec
    double T;

    virtual void init() {
        std::cout << "No init function." << std::endl;
    }

    virtual Signal process_single(uint32_t x, uint32_t t) {
        return process(x, 1, t);
    }

    virtual Signal process(uint32_t x, uint32_t f, uint32_t t) {
        std::cout << "No process function." << std::endl;
        return Signal::OP;
    }

    virtual void status() {
        std::cout << "No status function." << std::endl;
    }

    virtual std::string tag() = 0;

    bool operator < (const Solution &t) const { return mem < t.mem; }
};

#endif