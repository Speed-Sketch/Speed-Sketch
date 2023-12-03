#ifndef ALGO_OPSKETCH_HEADER
#define ALGO_OPSKETCH_HEADER

#include <algo/base.h>

class SpeedSketch : public Solution {
public:
    static constexpr int BYTES_PER_BUCKET = 4;

    typedef uint32_t CNT_TYPE;
    typedef struct {
        CNT_TYPE cnt;
    }Bucket;

    static constexpr CNT_TYPE CNT_MAX = ~0u;

    int K;  // number of array
    int W;  // width of array
    int G;  // global clock
    int seed_base;  // seed base of hash
    Bucket *buckets;  // sketch array

    SpeedSketch(uint32_t _B, double _T, double _mem, uint32_t _K);
    ~SpeedSketch();

    void init();
    void status();
    std::string tag();
    Signal process(uint32_t x, uint32_t f, uint32_t t);
};

#endif