#include <algo/strawman.h>
#include <murmur3.h>
#include <unistd.h>
#include <const.h>

Strawman::Strawman(uint32_t _B, double _T, double _mem) {
    B = _B;
    T = _T;
    mem = _mem;
    aging_time = B / T;
    sprintf(name, "Strawman");
    W = (int)(mem / BYTES_PER_BUCKET);
    mem = (double)W * BYTES_PER_BUCKET;
    buckets = new Bucket[W];
    seed_base = 2023;
}

Strawman::~Strawman() {
    if (buckets) {
        delete buckets;
    }
}

void Strawman::init() {
    G = 0;
    for (int i = 0; i < W; i++) {
        Bucket &bkt = buckets[i];
        bkt.lasttime = 0;
        bkt.token = B;
        bkt.footprint = 0;
    }
}

void Strawman::status() {
    printf("[%s]\n", name);
    printf("total bucket: %d   mem: %.3lfKB   B: %d   T: %.3lfMbps\n", W, mem / 1024, B, T*SEC_TO_MICROSEC/1024/1024*8);
}

std::string Strawman::tag() {
    return "Strawman";
}

Signal Strawman::process(uint32_t x, uint32_t f, uint32_t t) {
    G = t;
    int pos = MurmurHash3_x86_32((void*)&x, sizeof(uint32_t), seed_base) % W;
    Bucket &bucket = buckets[pos];
    
    if (bucket.footprint && bucket.footprint != x && bucket.token + T * (t - bucket.lasttime) < B) {
        return Signal::NOP;
    }
    if (bucket.footprint != x) {
        bucket.footprint = x;
        bucket.token = B;
    }
    // uint64_t token_incr = T * (t - bucket.lasttime);
    double token_incr = T * (t - bucket.lasttime);
    // bucket.token = min(bucket.token + token_incr, (uint64_t)B);
    bucket.token = min(bucket.token + token_incr, (double)B);
    bucket.lasttime = t;
    if (bucket.token >= f) {
        bucket.token -= f;
        return Signal::NOP;
    }
    return Signal::OP;
}
