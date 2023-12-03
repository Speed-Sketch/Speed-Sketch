#include <algo/hash_queue.h>

void HashQueue::init() {
    buckets.clear();
    while (!q.empty()) {
        q.pop();
    }
}

void HashQueue::status() {
    printf("[%s]\n", name);
    double req_mem = max_q_size * BYTES_PER_ELEMENT + max_user_num * BYTES_PER_BUCKET;
    printf("B: %d   T: %.3lf   sense_interval: %.3lfms   req_mem: %.3lfKB(%d/%d)\n", B, T, (double)sense_interval/1000, req_mem/1024, max_q_size, max_user_num);
}

std::string HashQueue::tag() {
    return "HashQueue";
}

Signal HashQueue::process(uint32_t x, uint32_t f, uint32_t t) {
    uint32_t clear_time = t - sense_interval;
    if (t < sense_interval) {
        clear_time = 0;
    }
    while (!q.empty()) {
        auto pkt = q.front();
        if (pkt.time > clear_time) {
            break;
        }
        Bucket &bucket = buckets[pkt.id];
        bucket.consumption -= pkt.size;
        if (bucket.consumption == 0) {
            buckets.erase(pkt.id);
        }
        q.pop();
    }
    if (!buckets.count(x)) {
        Bucket bucket = Bucket();
        bucket.consumption = 0;
    }
    Bucket &bucket = buckets[x];
    if (f + bucket.consumption > B) {
        return Signal::OP;
    }
    // printf("%u %lf\n", f, bucket.consumption);
    auto new_pkt = Element();
    new_pkt.id = x;
    new_pkt.size = f;
    new_pkt.time = t;
    q.push(new_pkt);
    max_q_size = max(max_q_size, (int)q.size());
    max_user_num = max(max_user_num, (int)buckets.size());
    bucket.consumption += f;
    return Signal::NOP;
}
