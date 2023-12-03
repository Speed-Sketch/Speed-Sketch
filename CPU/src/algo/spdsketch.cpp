#include <algo/spdsketch.h>
#include <murmur3.h>
#include <const.h>

SpeedSketch::SpeedSketch(uint32_t _B, double _T, double _mem, uint32_t _K)
: K(_K) {
    B = _B;
    T = _T;
    mem = _mem;

    sprintf(name, "SpeedSketch");
    W = (int)(mem / K / BYTES_PER_BUCKET);
    mem = (double)K * W * BYTES_PER_BUCKET;
    buckets = new Bucket[K * W];
    seed_base = 2022;
}

SpeedSketch::~SpeedSketch() {
    if (buckets) {
        delete buckets;
    }
}

void SpeedSketch::init() {
    G = 0;
    int total_bucket = K * W;
    for (int i = 0; i < total_bucket; ++i) {
        Bucket &bkt = buckets[i];
        bkt.cnt = 0;
    }
}

void SpeedSketch::status() {
    printf("[%s]\n", name);
    printf("total bucket: %d   mem: %.3lfKB   #Hash: %d    B: %u   T: %.3lfMbps\n", K*W, mem/1024, K, B, T*SEC_TO_MICROSEC/1024/1024*8);
}

std::string SpeedSketch::tag() {
    static char s[1000];
    sprintf(s, "SpeedSketch k=%d", K);
    return std::string(s);
}

Signal SpeedSketch::process(uint32_t x, uint32_t f, uint32_t t) {
    // simulate global clock (equal to packet arrived time now)
    int64_t G = T * t;
    // maximum
    CNT_TYPE min_usage = CNT_MAX;
    static int pos[10];
    static CNT_TYPE C[10];
    for (int i = 0; i < K; ++i) {
        pos[i] = MurmurHash3_x86_32((void*)&x, sizeof(uint32_t), seed_base+i) % W + W*i;
        Bucket &bucket = buckets[pos[i]];
        C[i] = max(0ll, (int64_t)bucket.cnt - G);
        min_usage = min(min_usage, C[i]);
    }
    // judge
    if (min_usage + f > B) {
        return Signal::OP;
    }
    CNT_TYPE min_target = CNT_MAX;
    for (int i = 0; i < K; ++i) {
        Bucket &bucket = buckets[pos[i]];
        CNT_TYPE target = min(C[i] + f, B) + G;
        min_target = min(min_target, target);
        bucket.cnt = max(min_target, bucket.cnt);
    }
    return Signal::NOP;
}
