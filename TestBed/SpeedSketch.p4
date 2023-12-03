/* -*- P4_16 -*- */
//need to handle ARP
#include <core.p4>
#include <tna.p4>


#define TB_CBS 150 // max token is 10MTU
#define TB_CBS_MINUS_1 149
#define TOKEN_WIDTH 16
#define BUCKET_SIZE1 65536 // The 1st level token bucket size
// #define BUCKET_SIZE2 65536 // The 2nd level token bucket size
// #define BUCKET_SIZE3 65536 // The 3rd level token bucket size
#define BUCKET_ID_WIDTH 16 // The bucket id width is 16b
#define TS_LAST_BITS 14  // The last n bits of timestamp are mapped to token
#define MIN_G 1000  // G in [MIN_G, 65535]
#define MIN_G_ADD_1 1001
#define INT16MAX_MINUS_MIN_G_MINUS_1 64535
#define MTU 1500
#define HEADER_LEN 28


/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
*************************************************************************/
enum bit<16> ether_type_t {
    TPID       = 0x8100,
    IPV4       = 0x0800,
    ARP        = 0x0806
}

enum bit<8>  ip_proto_t {
    ICMP  = 1,
    IGMP  = 2,
    TCP   = 6,
    UDP   = 17
}
struct ID_yes_no {
    bit<32>  ID;
    bit<32>  yes_no;
}

type bit<48> mac_addr_t;

/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/
/*  Define all the headers the program will recognize             */
/*  The actual sets of headers processed by each gress can differ */

/* Standard ethernet header */
header ethernet_h {
    mac_addr_t    dst_addr;
    mac_addr_t    src_addr;
    ether_type_t  ether_type;
}

header vlan_tag_h {
    bit<3>        pcp;
    bit<1>        cfi;
    bit<12>       vid;
    ether_type_t  ether_type;
}

header arp_h {
    bit<16>       htype;
    bit<16>       ptype;
    bit<8>        hlen;
    bit<8>        plen;
    bit<16>       opcode;
    mac_addr_t    hw_src_addr;
    bit<32>       proto_src_addr;
    mac_addr_t    hw_dst_addr;
    bit<32>       proto_dst_addr;
}

header ipv4_h {
    bit<4>       version;
    bit<4>       ihl;
    bit<7>       diffserv;
    bit<1>       res;
    bit<16>      total_len;
    bit<16>      identification;
    bit<3>       flags;
    bit<13>      frag_offset;
    bit<8>       ttl;
    bit<8>       protocol;
    bit<16>      hdr_checksum;
    bit<32>      src_addr;
    bit<32>      dst_addr;
}

header icmp_h {
    bit<16>  type_code;
    bit<16>  checksum;
}

header igmp_h {
    bit<16>  type_code;
    bit<16>  checksum;
}

header tcp_h {
    bit<16>  src_port;
    bit<16>  dst_port;
    bit<32>  seq_no;
    bit<32>  ack_no;
    bit<4>   data_offset;
    bit<4>   res;
    bit<8>   flags;
    bit<16>  window;
    bit<16>  checksum;
    bit<16>  urgent_ptr;
}

header udp_h {
    bit<16>  src_port;
    bit<16>  dst_port;
    bit<16>  len;
    bit<16>  checksum;
}
header ingress_mirror_header_t
{
    bit<48>    dst_addr;
    bit<48>    src_addr;
    bit<16>  ether_type;
    bit<8> layer_id;
    bit<16> index;
}

header sketch_h{
    bit<32> sketch_value; 
    //bit<8> output;
}
/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

/***********************  H E A D E R S  ************************/

struct my_ingress_headers_t {
    ethernet_h         ethernet;
    arp_h              arp;
    vlan_tag_h[2]      vlan_tag;
    ipv4_h             ipv4;
    icmp_h             icmp;
    igmp_h             igmp;
    tcp_h              tcp;
    udp_h              udp;
    sketch_h           sketch;
}


/******  G L O B A L   I N G R E S S   M E T A D A T A  *********/
@pa_container_size("ingress", "meta.ts", 16)
struct my_ingress_metadata_t {
    MirrorId_t session_id;
    ingress_mirror_header_t mirror_header;
    bit<32> ID;
    bit<32> output_ID;
    bit<32> yes_no;
    bit<16> collision;  //filter_value here
    bit<1> locked1;
    bit<1> locked2;
    bit<1> constant;
    bit<32> pktlen;
    bit<32> ihl;

    // TokenSketch metadata
    bit<16> min0;
    bit<16> tmp_G;
    bit<16> G_minus_B_add_1; // The global token G-B: We want: G-cnt < B

    bit<16> rnd_num;
    bit<32> rnd_mul_MTU_div_64k;
    bit<32> pktlen_mul_64k_div_MTU;

    bit<8> global_f;
    bit<8> flip_tag1;
    bit<8> flip_tag2;
    bit<8> flip_tag3;

    // Hash bucket idx;
    bit<BUCKET_ID_WIDTH> idx1;
    bit<BUCKET_ID_WIDTH> idx2;
    bit<BUCKET_ID_WIDTH> idx3;
    bit<BUCKET_ID_WIDTH> idx4;
    bit<BUCKET_ID_WIDTH> idx5;
    bit<BUCKET_ID_WIDTH> idx6;
    // timestamp: 256ns as one unit
    bit<16> ts;
    bit<16> cur_token;
    bit<16> last_token;
    bit<16> token_delta; // from time_delta to the token_delta

    // get token results: 0 means fail, otherwise store counter value
    bit<16> tmp_min1;
    bit<16> tmp_min2;
    bit<16> tmp_min3;
    bit<16> tmp_min4;
    bit<16> tmp_min5;
    bit<16> tmp_min6;
    bit<1> pass;
    bit<32> cond;  // if 0 <= cond < 65536, need token
    bit<32> get_token;
}

/***********************  P A R S E R  **************************/

parser IngressParser(packet_in        pkt,
    /* User */
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition meta_init;
    }

    state meta_init {
        meta.ID=0;
        meta.output_ID=0;
        meta.yes_no=0;
        meta.idx1=0;
        meta.idx2=0;
        meta.idx3=0;
        meta.idx4=0;
        meta.idx5=0;
        meta.idx6=0;
        meta.collision=0;
        meta.locked1=0;
        meta.locked2=0;
        meta.constant=0;
        meta.session_id=0;
        meta.pktlen = 0;
        meta.min0 = 0;
        meta.G_minus_B_add_1 = 0;
        meta.pass = 0;
        meta.get_token = 0;

        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        /*
         * The explicit cast allows us to use ternary matching on
         * serializable enum
         */
        transition select((bit<16>)hdr.ethernet.ether_type) {
            (bit<16>)ether_type_t.TPID &&& 0xEFFF :  parse_vlan_tag;
            (bit<16>)ether_type_t.IPV4            :  parse_ipv4;
            (bit<16>)ether_type_t.ARP             :  parse_arp;
            default :  accept;
        }
    }

    state parse_arp {
        pkt.extract(hdr.arp);
        transition accept;
    }
    state parse_vlan_tag {
        pkt.extract(hdr.vlan_tag.next);
        transition select(hdr.vlan_tag.last.ether_type) {
            ether_type_t.TPID :  parse_vlan_tag;
            ether_type_t.IPV4 :  parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        meta.pktlen = (bit<32>)hdr.ipv4.total_len;
        meta.ihl = (bit<32>)hdr.ipv4.ihl;
        transition select(hdr.ipv4.protocol) {
            1 : parse_icmp;
            2 : parse_igmp;
            6 : parse_tcp;
           17 : parse_udp;
            default : accept;
        }
    }


    state parse_icmp {
        pkt.extract(hdr.icmp);
        transition accept;
    }

    state parse_igmp {
        pkt.extract(hdr.igmp);
        transition accept;
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition accept;
    }


}

control Ingress(/* User */
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{

/* Hash Algorithm */
CRCPolynomial<bit<32>>(0xDB710641,false,false,false,32w0xFFFFFFFF,32w0xFFFFFFFF) crc32_1;
CRCPolynomial<bit<32>>(0x82608EDB,false,false,false,32w0xFFFFFFFF,32w0xFFFFFFFF) crc32_2;
CRCPolynomial<bit<32>>(0x04C11DB7,false,false,false,32w0xFFFFFFFF,32w0xFFFFFFFF) crc32_3;
CRCPolynomial<bit<32>>(0xEDB88320,false,false,false,32w0xFFFFFFFF,32w0xFFFFFFFF) crc32_4;
CRCPolynomial<bit<32>>(0xBA0DC66B,false,false,false,32w0xFFFFFFFF,32w0xFFFFFFFF) crc32_5;
CRCPolynomial<bit<32>>(0x992C1A4C,false,false,false,32w0xFFFFFFFF,32w0xFFFFFFFF) crc32_6;

Hash<bit<BUCKET_ID_WIDTH>>(HashAlgorithm_t.CUSTOM,crc32_1) hash_cal_1;
Hash<bit<BUCKET_ID_WIDTH>>(HashAlgorithm_t.CUSTOM,crc32_2) hash_cal_2;
Hash<bit<BUCKET_ID_WIDTH>>(HashAlgorithm_t.CUSTOM,crc32_3) hash_cal_3;
Hash<bit<BUCKET_ID_WIDTH>>(HashAlgorithm_t.CUSTOM,crc32_4) hash_cal_4;
Hash<bit<BUCKET_ID_WIDTH>>(HashAlgorithm_t.CUSTOM,crc32_5) hash_cal_5;
Hash<bit<BUCKET_ID_WIDTH>>(HashAlgorithm_t.CUSTOM,crc32_6) hash_cal_6;

action nop() {}

action get_pktlen() {
    meta.pktlen = meta.pktlen & 0x0000ffff;
}
table get_pktlen_tbl {
    actions = {get_pktlen;}
    default_action = get_pktlen();
    size=1;
}

action get_ihl() {
    meta.ihl = meta.ihl & 0x0000000f;
}
table get_ihl_tbl {
    actions = {get_ihl;}
    default_action = get_ihl();
    size=1;
}

action get_real_pktlen() {
    // meta.pktlen = meta.pktlen - meta.ihl;
    meta.pktlen = meta.pktlen - HEADER_LEN;
}
table get_real_pktlen_tbl {
    actions = {get_real_pktlen;}
    default_action = get_real_pktlen();
    size=1;
}

action get_cur_token(bit<16> token_num) {
    meta.cur_token = token_num;
}
table get_cur_token_tbl {
    key = {meta.ts: range;}
    actions = {get_cur_token; nop;}
    default_action = nop();
    size=8192;
}

Register<bit<16>, bit<2>>(size=1, initial_value=0) v4_cnt;
RegisterAction<bit<16>, bit<2>, bit<1>>(v4_cnt) set_v4_cnt={
    void apply(inout bit<16> register_data, out bit<1> result) {
        register_data = register_data + 1;
        result = 1;
    }
};
action set_new_cnt() {
    set_v4_cnt.execute(0);
}

Register<bit<16>, bit<32>>(size=1, initial_value=0) last_token;
RegisterAction<bit<16>, bit<32>, bit<16>>(last_token) get_token_delta={
    void apply(inout bit<16> register_data, out bit<16> result) {
        result = meta.cur_token - register_data;
        register_data = meta.cur_token;
    }
};
action get_token_delta_action() {
    meta.token_delta = get_token_delta.execute(0);
}
table get_token_delta_tbl {
    actions = {get_token_delta_action;}
    default_action = get_token_delta_action();
    size = 1;
}

action token_delta_overflow_action(bit<16> token_max) {
    meta.token_delta = meta.token_delta + token_max;
}
action token_set_limit(bit<16> token_max) {
    meta.token_delta = token_max; // limit the max token_delta as CBS
}
table get_not_overflow_token_delta_tbl {
    key = {meta.token_delta: range;}
    actions = {token_delta_overflow_action;token_set_limit; nop;}
    default_action = nop();
    size = 128;
}

// The global token: G
Register<bit<TOKEN_WIDTH>, bit<32>>(size=1, initial_value=0) G_store;
RegisterAction<bit<TOKEN_WIDTH>, bit<32>, bit<TOKEN_WIDTH>>(G_store) get_new_G={
    void apply(inout bit<TOKEN_WIDTH> register_data, out bit<TOKEN_WIDTH> result) {
       if ( meta.token_delta + register_data < 16w32000 ) {
           result = register_data + meta.token_delta;
           register_data = register_data + meta.token_delta;
       } else {
           result = MIN_G; // Get the new value
           register_data = MIN_G;
       }
    }
};
action get_cur_G() {
    meta.min0 = get_new_G.execute(0);
}
table get_G_tbl {
    actions = {get_cur_G;}
    default_action = get_cur_G();
    size=1;
}

action get_G_minus_B_add_1() {
    meta.G_minus_B_add_1 = meta.min0 - TB_CBS_MINUS_1;
}
table get_G_minus_B_add_1_tbl {
    actions = {get_G_minus_B_add_1;}
    default_action = get_G_minus_B_add_1();
    size=1;
}

// The hash operations
action get_hash_idxs1() {
    meta.idx1 = hash_cal_1.get({hdr.ipv4.src_addr, hdr.ipv4.src_addr})[15:0];
    meta.idx2 = hash_cal_2.get({hdr.ipv4.src_addr});
}
table get_hash_tbl1 {
    actions = {get_hash_idxs1;}
    default_action = get_hash_idxs1();
    size = 1;
}

Register<bit<8>, bit<32>>(size=1, initial_value=0) global_f_store;
RegisterAction<bit<8>, bit<32>, bit<8>>(global_f_store) get_global_f={
    void apply(inout bit<8> register_data, out bit<8> result) {
        result = register_data;
    }
};
RegisterAction<bit<8>, bit<32>, bit<8>>(global_f_store) flip_global_f={
    void apply(inout bit<8> register_data, out bit<8> result) {
        register_data = register_data + 1;
        result = register_data;
    }
};
action get_global_f_action() {
    meta.global_f = get_global_f.execute(0);
}
table get_global_f_tbl {
    actions = {get_global_f_action;}
    default_action = get_global_f_action();
    size=1;
}
action flip_global_f_action() {
    meta.global_f = flip_global_f.execute(0);
}
table flip_global_f_tbl {
    actions = {flip_global_f_action;}
    default_action = flip_global_f_action();
    size=1;
}

Random<bit<16>>() rnd;

action get_pktlen_mul_64k_div_MTU_action(bit<32> result) {
    meta.pktlen_mul_64k_div_MTU = result;
}

table get_pktlen_mul_64k_div_MTU_tbl {
    key = {meta.pktlen: exact;}
    actions = {get_pktlen_mul_64k_div_MTU_action; nop;}
    default_action = nop();
    size=1501;
}

action get_cond_action() {
    meta.cond = meta.pktlen_mul_64k_div_MTU - (bit<32>)meta.rnd_num;
}
table get_cond_tbl {
    actions = {get_cond_action;}
    default_action = get_cond_action();
    size=1;
}

/* level 1 */
Register<bit<8>, bit<16>>(size=BUCKET_SIZE1, initial_value=0) f1_store;
RegisterAction<bit<8>, bit<16>, bit<8>>(f1_store) check_f1={
    void apply(inout bit<8> register_data, out bit<8> result) {
        if (register_data == meta.global_f) {
            result = 0;
        } else {
            result = 8w1;
        }
        register_data = meta.global_f;
    }
};
action check_f1_action() {
    meta.flip_tag1 = check_f1.execute(meta.idx1);
}
table check_f1_tbl {
    actions = {check_f1_action;}
    default_action = check_f1_action();
    size=1;
}

/* token bucket recording */
Register<bit<TOKEN_WIDTH>, bit<16>>(size=BUCKET_SIZE1, initial_value=0) token_bucket1;
RegisterAction<bit<TOKEN_WIDTH>, bit<16>, bit<TOKEN_WIDTH>>(token_bucket1) get_token_1={
    void apply(inout bit<TOKEN_WIDTH> register_data, out bit<TOKEN_WIDTH> result) {
        // G_minus_B_add_1 = G-B+1
        if (register_data >= meta.G_minus_B_add_1 && register_data < meta.min0) {
            register_data = register_data + 1;
        }
        if (register_data < meta.G_minus_B_add_1) {
            register_data = meta.G_minus_B_add_1;
        }
        result = min(register_data, meta.min0);
    }
};
action get_token_1_action() {
    meta.min0 = get_token_1.execute(meta.idx1);
}
table get_token_1_tbl {
    actions = {get_token_1_action;}
    default_action = get_token_1_action();
    size=1;
}
RegisterAction<bit<TOKEN_WIDTH>, bit<16>, bit<TOKEN_WIDTH>>(token_bucket1) check_token_1={
    void apply(inout bit<TOKEN_WIDTH> register_data, out bit<TOKEN_WIDTH> result) {
        result = min(register_data, meta.min0);
    }
};
action check_token_1_action() {
    meta.min0 = check_token_1.execute(meta.idx1);
}
table check_token_1_tbl {
    actions = {check_token_1_action;}
    default_action = check_token_1_action();
    size=1;
}
RegisterAction<bit<TOKEN_WIDTH>, bit<16>, void>(token_bucket1) flip_token_1={
    void apply(inout bit<TOKEN_WIDTH> register_data) {
        register_data = meta.G_minus_B_add_1;
    }
};
action flip_token_1_action() {
    flip_token_1.execute(meta.idx1);
}
table flip_token_1_tbl {
    actions = {flip_token_1_action;}
    default_action = flip_token_1_action();
    size=1;
}

/* counter for the values */
// DirectCounter<bit<64>>(CounterType_t.PACKETS) mirror_stats;
// DirectCounter<bit<64>>(CounterType_t.PACKETS) filter_stats;
// DirectCounter<bit<64>>(CounterType_t.PACKETS) mirror_set_after_stats;

/* arp packets processing */
action unicast_send(PortId_t port) {
    ig_tm_md.ucast_egress_port = port;
    ig_tm_md.bypass_egress=1;
}
action unicast_send_1() {
    ig_tm_md.ucast_egress_port = 160;
    ig_tm_md.bypass_egress=1;
}
action unicast_send_2() {
    ig_tm_md.ucast_egress_port = 128;
    ig_tm_md.bypass_egress=1;
}
action drop() {
    ig_tm_md.bypass_egress=1;
    ig_dprsr_md.drop_ctl = 1;
}
table arp_host {
    key = { hdr.arp.proto_dst_addr : exact; }
    actions = { unicast_send; drop; }
    default_action = drop();
    size = 512;
}

/* ipv4 forwarding */
table ipv4_host {
    key = { hdr.ipv4.dst_addr : exact; }
    actions = { unicast_send; unicast_send_2; drop; }
    default_action = unicast_send(128);
    size = 512;
}

action get_meta_ts(){
    meta.ts = ig_prsr_md.global_tstamp[23:8];
}

@stage(0) table meta_ts_tbl {
    actions={get_meta_ts;}
    default_action=get_meta_ts();
    size=1;
}

    apply {
        // 100Mbps--> ~12.5K MTU/s; 2^8ns*500Mbps=16B; 2^16*500Mbps=4.1KB
        meta_ts_tbl.apply();
        if (hdr.arp.isValid()) {
            arp_host.apply();
        } else if (hdr.ipv4.isValid()) {
            ipv4_host.apply();
            // Convert time to the Bytes
            // Get correct packet len
            get_pktlen_tbl.apply();
            get_ihl_tbl.apply();
            get_real_pktlen_tbl.apply();
            // Get current token
            get_cur_token_tbl.apply(); 
            // Get token_delta
            set_new_cnt();
            get_token_delta_tbl.apply();
            get_not_overflow_token_delta_tbl.apply();
            // Update G
            get_G_tbl.apply();
            if (MIN_G != meta.min0) {
                get_global_f_tbl.apply();
            } else {
                // G overflow, flip global F
                flip_global_f_tbl.apply();
            }

            // random sampling
            meta.rnd_num = rnd.get();
            // get_rnd_mul_MTU_div_64k_tbl.apply();
            get_pktlen_mul_64k_div_MTU_tbl.apply();
            get_cond_tbl.apply();

            // Get G-B+1
            get_G_minus_B_add_1_tbl.apply();
            //calculating the hashing index, [src addr] is the key
            get_hash_tbl1.apply();

            // level 1
            check_f1_tbl.apply();
            meta.tmp_min1 = meta.min0;
            if (meta.flip_tag1 == 1) {
                flip_token_1_tbl.apply();
                meta.pass = 1;
            } else {
                if (meta.cond < 65536) {
                    meta.get_token = 1;
                    get_token_1_tbl.apply();
                } else {
                    check_token_1_tbl.apply();
                }
                if (meta.min0 != meta.tmp_min1) {
                    meta.pass = 1;
                } else if (hdr.udp.isValid()) {
                    drop();
                }
            }

            // if (meta.pass == 0) {
            //     // all levels failed
            //     hdr.ipv4.diffserv = 1;
            //     drop();
            // }
        }
    }
}


control IngressDeparser(packet_out pkt,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{

    Checksum() ipv4_checksum;
    Checksum() tcp_csum;
    Mirror() mirror;
    apply {
        if (hdr.ipv4.isValid()) {
            hdr.ipv4.hdr_checksum = ipv4_checksum.update({
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.res,
                hdr.ipv4.total_len,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.frag_offset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr
            });
        }
        /*
        if(hdr.tcp.isValid()){
            hdr.tcp.checksum = tcp_csum.update({
                    hdr.tcp.src_port, hdr.tcp.dst_port, hdr.tcp.seq_no,
                    hdr.tcp.ack_no, hdr.tcp.data_offset, hdr.tcp.res,
                    hdr.tcp.flags, hdr.tcp.window, hdr.tcp.urgent_ptr});
        }
        */
        if (ig_dprsr_md.mirror_type == 2)
            mirror.emit<ingress_mirror_header_t>(meta.session_id,meta.mirror_header);
        pkt.emit(hdr);
    }
}

/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

/***********************  H E A D E R S  ************************/

struct my_egress_headers_t {
    ethernet_h         ethernet;
    vlan_tag_h[2]       vlan_tag;
    ipv4_h          ipv4;
}


/********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {

}

/***********************  P A R S E R  **************************/

parser EgressParser(packet_in        pkt,
    /* User */
    out my_egress_headers_t          hdr,
    out my_egress_metadata_t         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

/***************** M A T C H - A C T I O N  *********************/

control Egress(
    /* User */
    inout my_egress_headers_t                          hdr,
    inout my_egress_metadata_t                         meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{
    apply { }
}

/*********************  D E P A R S E R  ************************/

control EgressDeparser(packet_out pkt,
    /* User */
    inout my_egress_headers_t                       hdr,
    in    my_egress_metadata_t                      meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    apply {
          pkt.emit(hdr);
    }
}

/************ F I N A L   P A C K A G E ******************************/
Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;
