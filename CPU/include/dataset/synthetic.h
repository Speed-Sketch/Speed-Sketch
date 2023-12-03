#ifndef DATASET_SYNTHETIC_HEADER
#define DATASET_SYNTHETIC_HEADER


#include <iostream>
#include <fstream>
#include <algorithm>
#include <dataset/base.h>
#include <algo/hash_table.h>
#include <utils.h>
#include <const.h>
#include <murmur3.h>
#include <climits>
#include <stack>
#include <math.h>

class Synthetic : public Dataset {
public:
    vector<uint32_t>footprints;
    Synthetic(uint32_t t_seed = 0x123) { seed = t_seed; }

    void read(string file_name, int size_limit) {
        cerr << "Synthetic::read undefined\n";
    }
    void generateBurst(int flow_num, double begin_time, double B, double interval, double duration, uint32_t size) {
        footprints.clear();
        flow.clear();
        for (int i = 0; i < flow_num; i++) {
            static char key[40];
            sprintf(key, "arandomkeyforburst[%02d]", i);
            uint32_t footprint = MurmurHash3_x86_32(key, strlen(key), 0x123);
            footprints.push_back(footprint);
            double offset = rand() % 100 * 1. / SEC_TO_MILISEC; // second
            for (double t = 0; t < duration; t += interval) for (uint32_t _ = 0; _ < B / size; _ ++)
                flow.push_back(Packet{0, 0, 0, 0, 0, size, begin_time + t + offset, footprint});
        }
        sort(flow.begin(), flow.end(), [](const Packet &a, const Packet &b){return a.timestamp < b.timestamp;});
    }
    void generatePersistent(int flow_num, double begin_time, double interval, double duration, uint32_t size) {
        footprints.clear();
        flow.clear();
        for (int i = 0; i < flow_num; i++) {
            static char key[40];
            sprintf(key, "arandomkeyforpersistent[%02d]", i);
            uint32_t footprint = MurmurHash3_x86_32(key, strlen(key), 0x123 + rand());
            footprints.push_back(footprint);
            double offset = rand() % 100 * 1. / SEC_TO_MILISEC; // second
            // double offset = 4. / SEC_TO_MILISEC;
            for (double t = 0; t < duration; t += interval)
                flow.push_back(Packet{0, 0, 0, 0, 0, size, begin_time + t + offset, footprint});
        }
        sort(flow.begin(), flow.end(), [](const Packet &a, const Packet &b){return a.timestamp < b.timestamp;});
    }
    void generateRealistic(uint32_t B, double T, uint64_t totSize, double z_size, double z_speed, double length) {
        footprints.clear();
        flow.clear();
        const uint32_t MAX_SIZE = T * SEC_TO_MICROSEC * length / 2;
        // cerr << "MAXSIZE: " << MAX_SIZE << '\n';
        vector<uint32_t>sizes;
        vector<double>speeds;
        uint64_t curSize = 0;
        for (int i = 1; curSize < totSize; i++) {
            sizes.push_back(MAX_SIZE / pow(i, z_size)),
            curSize += sizes.back();
            if (sizes.back() < 1000u) {
                printf("WARNING: size decrease too fast\n");
                break;
            }
        }
        const double MAX_SPEED = T / 2 * pow(sizes.size(), z_speed);
        for (int i = 0; i < (int)sizes.size(); i++) {
            speeds.push_back(MAX_SPEED / pow(i + 1, z_speed));
            if (B + speeds[i] * length * SEC_TO_MICROSEC < sizes[i]) {
                static int flg = 0;
                if (!flg) printf("WARNING: speed too slow or duration too short, not enough for size\n");
                flg = 1;
                sizes[i] = B + speeds[i] * length * SEC_TO_MICROSEC;
            }
        }
        // printf("speeds.front() = %.3lf\n", speeds.front());
        // printf("speeds.back() = %.3lf\n", speeds.back());
        uint32_t flow_num = sizes.size();
        // printf("flow_num = %u\n", flow_num);
        // printf("curSize = %lu\n", curSize);
        for (uint32_t i = 0; i < flow_num; i++)
            swap(speeds[i], speeds[i - rand() % min(i + 1, uint32_t(pow(i + 10, 0.5)))]);
        for (uint32_t i = 0; i < flow_num; i++) {
            footprints.push_back(i);

            const uint32_t totSize = sizes[i]; // byte
            const uint32_t duration = totSize / speeds[i]; // microsec
            const int n = 31 - __builtin_clz(max(1ull, (uint64_t) duration * SEC_TO_MILISEC / SEC_TO_MICROSEC / 1));
            stack<pair<int,uint32_t>>st;
            st.push(make_pair(0, totSize));
            uint32_t curTime = (rand() + 1u * rand() * rand()) % uint64_t(length * SEC_TO_MICROSEC);
            HashTable gt(B, T, 0);
            gt.init();
            
            uint32_t qu = 0;
            auto proceed=[&](){
                curTime += duration >> n;
                while (qu) {
                    uint32_t x = qu;
                    if (qu > 1500u) x = rand() % 1200 + 300;
                    flow.push_back(Packet{0, 0, 0, 0, 0, x, 1.0 * (curTime + rand() % (duration >> n)) / SEC_TO_MICROSEC, i});
                    qu -= x;
                }
                for (int _ = 0; _ < 10; _++) {
                    uint32_t x = rand() % 1200 + 300;
                    flow.push_back(Packet{0, 0, 0, 0, 0, x, 1.0 * (curTime + rand() % (duration >> n)) / SEC_TO_MICROSEC, i});
                    if (qu <= x) {
                        qu = 0;
                        break;
                    }
                    qu -= x;
                }
                qu *= pow(0.97, (duration >> n) / 1000.0);
            };
            while (st.size()) {
                auto [dep, size] = st.top();
                st.pop();
                double b = (dep <= n / 3 ? 0.6 : 0.7);
                if (dep == n || size <= 1500) {
                    qu += size;
                    for (int i = 0; i < (1 << (n - dep)); i++) proceed();
                }
                else if (rand()%2) {
                    st.push(make_pair(dep + 1, uint32_t(size * b)));
                    st.push(make_pair(dep + 1, size - uint32_t(size * b)));
                }
                else {
                    st.push(make_pair(dep + 1, size - uint32_t(size * b)));
                    st.push(make_pair(dep + 1, uint32_t(size * b)));
                }
            }
        }
        sort(flow.begin(), flow.end(), [](const Packet &a, const Packet &b){return a.timestamp < b.timestamp;});
        printf("flow_size = %u\n", flowsize());
        printf("lasttime = %.3lf\n", flow.back().timestamp);
    }
};

#endif