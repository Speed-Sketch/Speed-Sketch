#ifndef ALGO_HASHTABLE_HEADER
#define ALGO_HASHTABLE_HEADER

#include <algo/base.h>
#include <unordered_map>
#include <vector>
using std::unordered_map;

class HashTable : public Solution {
public:
    static constexpr int BYTES_PER_BUCKET = 16;
    typedef struct {
        double token;
        uint32_t lasttime;
    }Bucket;

    double mem;
    int W;
    unordered_map<uint32_t, Bucket> buckets;

    HashTable(uint32_t _B, double _T, double mem) {
        B = _B;
        T = _T;
        W = (int)(mem / BYTES_PER_BUCKET);
        mem = (double)W * BYTES_PER_BUCKET;
        sprintf(name, "HashTable");
    }
    ~HashTable() {}

    void init();
    void status();
    std::string tag();
    Signal process(uint32_t x, uint32_t f, uint32_t t);
};

#endif