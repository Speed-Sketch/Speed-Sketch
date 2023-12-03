from netaddr import IPAddress
import math

p4 = bfrt.SpeedSketch.pipe

# This function can clear all the tables and later on other fixed objects
# once bfrt support is added.
def clear_all(verbose=True, batching=True):
    global p4
    global bfrt
            
    # The order is important. We do want to clear from the top, i.e.
    # delete objects that use other objects, e.g. table entries use
    # selector groups and selector groups use action profile members

    for table_types in (['MATCH_DIRECT', 'MATCH_INDIRECT_SELECTOR'], ['SELECTOR'], ['ACTION_PROFILE']):
        for table in p4.info(return_info=True, print_info=False):
            if table['type'] in table_types:
                if verbose:
                    print("Clearing table {:<40} ... ".format(table['full_name']), end='', flush=True)
            table['node'].clear(batch=batching)
            if verbose:
                print('Done')

# clear_all(verbose=True)

print(' ')
print('Add table entries now ')
print(' ')

# arp tables
arp_tbl = p4.Ingress.arp_host
arp_tbl.clear()
arp_tbl.add_with_unicast_send( proto_dst_addr=IPAddress('10.0.0.2'), port=136)
arp_tbl.add_with_unicast_send( proto_dst_addr=IPAddress('10.0.0.1'), port=128)

# ipv4 table
ipv4_tbl =  p4.Ingress.ipv4_host
ipv4_tbl.clear()
ipv4_tbl.add_with_unicast_send( dst_addr=IPAddress('10.0.0.2'),  port=136)
ipv4_tbl.add_with_unicast_send( dst_addr=IPAddress('10.0.0.1'),  port=128)

# configure the token value
#  0-2^14 (each 8 --> 0 value)
ts2token_tbl = p4.Ingress.get_cur_token_tbl
ts2token_tbl.clear()
target_bandwith = 100
step_v = 1500 * 32 * 1000 / 1024 / target_bandwith
print('stepv=', step_v)
k = 1
# print('k =', k)
for idx in range(0, int((1<<16)/step_v)):
    val_start = int(idx*step_v)
    val_end = (1<<16) - 1 if idx == int((1<<16)/step_v) - 1 else int((idx+1)*step_v-1)
    print(val_start, val_end, int(k * idx))
    ts2token_tbl.add_with_get_cur_token( ts_start=val_start, ts_end=val_end, token_num=int(k * idx ) )
    token_max = int(k * idx ) + 1
# print("Add the entry %d idx: %x -> %x" % (idx, val_start, val_end) )
print('token max=', token_max)
print("add the ts->token")
overflow_tbl = p4.Ingress.get_not_overflow_token_delta_tbl
overflow_tbl.clear()
overflow_tbl.add_with_token_delta_overflow_action(token_delta_start=(1<<11)+1, token_delta_end=(1<<16)-1, token_max=token_max)

div_tbl = p4.Ingress.get_pktlen_mul_64k_div_MTU_tbl
div_tbl.clear()
for pktlen in range(1501):
    x = pktlen * 65536 // 1500
    # print('add table entry', pktlen, x)
    div_tbl.add_with_get_pktlen_mul_64k_div_MTU_action(pktlen=pktlen, result=x)


bfrt.complete_operations()
print("finish the add")
