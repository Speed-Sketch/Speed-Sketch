#ifndef ALGO_HASH_QUEUE_HEADER
#define ALGO_HASH_QUEUE_HEADER

#include <algo/base.h>
#include <unordered_map>
#include <vector>
#include <queue>
using std::unordered_map;
using std::queue;

class HashQueue : public Solution {
public:
    static constexpr int BYTES_PER_ELEMENT = 12;
    static constexpr int BYTES_PER_BUCKET = 4;
    typedef struct {
        uint32_t id;
        uint32_t size;
        uint32_t time;
    }Element;

    typedef struct {
        double consumption;
    }Bucket;

    int max_q_size, max_user_num;
    uint32_t sense_interval;
    unordered_map<uint32_t, Bucket> buckets;
    queue<Element> q;

    HashQueue(uint32_t _B, double _T) {
        B = _B; T = _T;
        sense_interval = (uint32_t)((double)_B / _T);
        max_q_size = 0;
        max_user_num = 0;
        sprintf(name, "HashQueue");
    }
    ~HashQueue() {}

    void init();
    void status();
    std::string tag();
    Signal process(uint32_t x, uint32_t f, uint32_t t);
};

#endif