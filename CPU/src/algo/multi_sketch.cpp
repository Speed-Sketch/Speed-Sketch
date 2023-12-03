#include <algo/multi_sketch.h>
#include <const.h>
#include <utils.h>

void MultiSketch::init() {
    for (int i = 0; i < num_sketches; ++i) {
        if (sks[i]) delete sks[i];
        sks[i] = new StingyCU((int)per_mem, 2);
        start_time[i] = 0;
    }
}

void MultiSketch::status() {
    printf("[%s]\n", name);
    printf("B: %d   T: %.3lf   [m=%d] Interval: %.3lfms  buckets_per_sketch: %d\n", B, T, num_sketches, (double)interval/1000, (int)per_mem);
}

std::string MultiSketch::tag() {
    return "MultiSketch";
}

inline int next_idx(int idx, int m, int step = 1) {
    return (idx + step) % m;
}

inline int previous_idx(int idx, int m, int step = 1) {
    return (idx - step + m) % m;
}

Signal MultiSketch::process(uint32_t x, uint32_t f, uint32_t t) {
    // sampling
    int rd = RandUint32() % MTU;
    if (rd >= f) {
        // printf("drop! %u %d %u\n", x, rd, f);
        return Signal::NOP;
    }
    int now_idx = (t / interval) % num_sketches;
    uint32_t now_start_time = (t / interval) * interval;
    double now_token = B;
    int64_t sketch_time = (int64_t)now_start_time - (num_sketches-1) * interval;
    for (int i = next_idx(now_idx, num_sketches); i != now_idx; i = next_idx(i, num_sketches), sketch_time += interval) {
        if (sketch_time >= 0 && sketch_time != start_time[i]) {
            // build new sketch
            if (sks[i]) delete sks[i];
            sks[i] = new StingyCU((int)per_mem, 2);
            start_time[i] = sketch_time;
        }
        int freq = sks[i]->Query((char*)(&x));
        double old_token = now_token;
        now_token = min(now_token + T * interval - freq * MTU, (double)B);
        // printf("[%d - %u - %d]query freq: %d  %.2lf / %.2lf\n", i, start_time[i], sketch_time, freq, now_token, old_token);
        now_token = max(now_token, 0.);
    }
    // calc now sketch
    if (now_start_time != start_time[now_idx]) {
        // build new sketch
        if (sks[now_idx]) delete sks[now_idx];
        sks[now_idx] = new StingyCU((int)per_mem, 2);
        // printf("new sketch! %u %lld\n", start_time[now_idx], sketch_time);
        start_time[now_idx] = now_start_time;
    }
    int freq = sks[now_idx]->Query((char*)(&x));
    double old_token = now_token;
    now_token = min(now_token + T * (t - now_start_time) - freq * MTU, (double)B);
    // printf("[%d]query freq: %d  %.2lf / %.2lf\n", now_idx, freq, now_token, old_token);
    if (now_token < f) {
        // printf("discard\n");
        return Signal::OP;
    }
    sks[now_idx]->Insert((char*)(&x));
    // freq = sks[now_idx]->Query((char*)(&x));
    // printf("final freq: %d\n", freq);
    return Signal::NOP;
}