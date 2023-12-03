#include <utils.h>
#include <const.h>

#include <dataset/caida.h>
#include <dataset/imc.h>
#include <dataset/synthetic.h>

#include <algo/strawman.h>
#include <algo/hash_table.h>
#include <algo/spdsketch.h>
#include <algo/hash_queue.h>
#include <algo/multi_sketch.h>

#include <string.h>
#include <fstream>
#include <sstream>
#include <iostream>
#include <vector>
#include <map>
#include <cmath>
#include <algorithm>
#include <cassert>
#include <stdint.h>
#include <numeric>
#include <stack>

using namespace std;

#define ft first
#define sc second

void PrecisionTest(Dataset& flow, Solution* gt, vector<Solution*>& _algs, bool init_first = true) {
    // gt = algs[0], others = algs[1~]
    vector<Solution*> algs = {gt};
    for (auto alg : _algs) {
        algs.push_back(alg);
    }
    if (init_first) {
        for (auto alg : algs) {
            alg->init();
        }
    }

    int flowsize = flow.flowsize();
    double begin_time = flow[0].timestamp;
    vector< map<uint32_t, uint32_t> > drop_bytes;
    map<uint32_t, uint32_t> flow_cnt;
    for (auto alg : algs) {
        drop_bytes.push_back(map<uint32_t, uint32_t>());
    }
    int sum = 0;
    for (auto packet : flow.flow) {
        uint32_t t_uint = (uint32_t)((packet.timestamp - begin_time) * SEC_TO_MICROSEC);
        uint32_t t_size = packet.size;
        if (flow_cnt.count(packet.footprint) == 0) {
            flow_cnt[packet.footprint] = 0;
        }
        flow_cnt[packet.footprint]++;

        for (int i = 0; i < algs.size(); ++i) {
            Solution* alg = algs[i];
            Signal alg_res = alg->process(packet.footprint, t_size, t_uint);
            if (alg_res == Signal::OP) {
                auto &drop_map = drop_bytes[i];
                if (drop_map.count(packet.footprint) == 0) {
                    drop_map[packet.footprint] = 0;
                }
                drop_map[packet.footprint] += t_size;
            }
        }
        packet.size = t_size;
    }

    printf("\n\n====== Precision Test ======\n");
    printf("# Affected Flows: %lu  Count Packet: %d  # Flows: %lu\n\n", drop_bytes[0].size(), sum, flow_cnt.size());
    for (int i = 1; i < algs.size(); ++i) {
        int n_error = drop_bytes[0].size();
        double ae = 0, re = 0;
        for (auto drop_flow: drop_bytes[0]) {
            uint32_t alg_drop = drop_bytes[i][drop_flow.first];
            uint32_t error = ANY_ABS(drop_flow.second, alg_drop);
            ae += error;
            re += error / drop_flow.second;
        }
        algs[i]->status();
        printf("AE: %.3lf (%u)    RE: %.3lf (%u)\n", ae / n_error, (uint32_t)ae, re / n_error, re);
    }
}

int main(int argc, char *argv[])
{
    srand(time(0));

    int flow_size = 1e7;

    double sense_interval = 20;  // ms
    double bandwidth = 10 * MEGABYTES;  // bps
    uint32_t B = bandwidth / KILOBYTES / 8 * sense_interval;  // bandwidth(kbps) * sense_interval / 8
    double T = bandwidth / 8 / SEC_TO_MICROSEC;  // bandwidth / 8

    // ============= LOAD DATA =============
    // CAIDA18 dataset = CAIDA18();
    // dataset.read("data/01.dat", flow_size);
    // IMCDataset dataset = IMCDataset();
    // dataset.read("data/IMC/univ1/imc_1.dat", flow_size);
    Synthetic dataset;
    dataset.generateRealistic(B, T, 1e7 * 800, 0.5, 0.05, 7);
    // dataset.generateBurst(12500, 0, 2*B, 2*sense_interval/SEC_TO_MILISEC, 1., MTU);
    dataset.trim(flow_size);
    printf("flowsize: %d   duration: %.3lf\n", dataset.flowsize(), dataset.duration());

    double duration = dataset.duration();
    double err_spd_threshold = 10 * KILOBYTES;

    HashTable *hash_table = new HashTable(B, T, 0);
    vector<Solution*> algs;
    // HashQueue *hq = new HashQueue(B, T);
    // algs.push_back(hq);
    for (int i = 1; i <= 10; ++i) {
        double mem_size = i * 100 * KILOBYTES;
        SpeedSketch *ss = new SpeedSketch(B, T, mem_size, 3);
        sprintf(ss->name, "%s(k=3, mem=%dKB)", ss->name, i * 100);
        SpeedSketch *ss2 = new SpeedSketch(B, T, mem_size, 1);
        sprintf(ss2->name, "%s(k=1, mem=%dKB)", ss2->name, i * 100);
        Strawman *fc = new Strawman(B, T, mem_size);
        sprintf(fc->name, "%s(mem=%dKB)", fc->name, i * 100);
        // MultiSketch *ms = new MultiSketch(B, T, 20, mem_size, 4000);  // 4ms interval
        algs.push_back(ss);
        algs.push_back(ss2);
        algs.push_back(fc);
        // algs.push_back(ms);
    }
    PrecisionTest(dataset, hash_table, algs, true);
    delete hash_table;
    for (auto alg: algs) {
        delete alg;
    }

    return 0;
}
