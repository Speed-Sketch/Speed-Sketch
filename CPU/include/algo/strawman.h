#ifndef ALGO_STRAWMAN_HEADER
#define ALGO_STRAWMAN_HEADER

#include <algo/base.h>
#include <map>
#include <vector>
using std::map;

class Strawman : public Solution {
public:
    static constexpr int BYTES_PER_BUCKET = 16;
    typedef struct {
        // uint32_t token;
        double token;
        uint32_t lasttime;
        uint64_t footprint;
    }Bucket;

    uint32_t G; // global clock
    uint32_t aging_time;
    int W; // number of buckets
    Bucket *buckets;
    int seed_base;  // seed base of hash

    Strawman(uint32_t _B, double _T, double _mem);
    ~Strawman();

    void init();
    void status();
    std::string tag();
    Signal process(uint32_t x, uint32_t f, uint32_t t);
};

#endif