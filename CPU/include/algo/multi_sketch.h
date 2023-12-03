#ifndef ALGO_MULTI_SKETCH_HEADER
#define ALGO_MULTI_SKETCH_HEADER

#include <algo/base.h>
#include <unordered_map>
#include <vector>
#include <queue>
#include <external/stingy/stingy_cu.h>
using std::unordered_map;
using std::queue;

#define MAX_NUM_SKETCHES 1000

class MultiSketch : public Solution {
public:

    StingyCU *sks[MAX_NUM_SKETCHES+1];
    uint32_t interval;
    uint32_t start_time[MAX_NUM_SKETCHES+1];
    double per_mem;
    int num_sketches;

    MultiSketch(uint32_t _B, double _T, int m, double _mem, uint32_t _interval) {
        B = _B; T = _T;
        sprintf(name, "MultiSketch(StingyCU)");
        interval = _interval;
        num_sketches = m;
        per_mem = _mem / num_sketches;
        for (int i = 0; i < num_sketches; ++i) {
            sks[i] = new StingyCU((int)per_mem, 2);
            start_time[i] = 0;
        }
    }
    ~MultiSketch() {
        for (int i = 0; i < num_sketches; ++i) {
            delete sks[i];
        }
    }

    void init();
    void status();
    std::string tag();
    Signal process(uint32_t x, uint32_t f, uint32_t t);
};

#endif