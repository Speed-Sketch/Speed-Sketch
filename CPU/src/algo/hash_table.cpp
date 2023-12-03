#include <algo/hash_table.h>

void HashTable::init() {
    buckets.clear();
}

void HashTable::status() {
    printf("[%s]\n", name);
    printf("B: %d   T: %.3lf\n", B, T);
}

std::string HashTable::tag() {
    return "HashTable";
}

Signal HashTable::process(uint32_t x, uint32_t f, uint32_t t) {
    if (!buckets.count(x)) {
        // if ((int)buckets.size() == W) return TBSignal::GREEN;
        Bucket bucket = Bucket();
        bucket.lasttime = 0;
        bucket.token = B;
        buckets[x] = bucket;
    }
    Bucket &bucket = buckets[x];
    double token_incr = T * (t - bucket.lasttime);
    double tmp_token = bucket.token;
    bucket.token = min(bucket.token + token_incr, (double)B);
    bucket.lasttime = t;
    if (bucket.token >= f) {
        bucket.token -= f;
        return Signal::NOP;
    }
    return Signal::OP;
}
