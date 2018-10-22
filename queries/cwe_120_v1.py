#============================================================================================================
# CWE-120: Buffer Copy without Checking Size of Input
#
# Vuln Info: A trivial way to cause this vulnerability is using the gets() function which is not secure.
# Ex:
#     bytes_received = gets(input);                                 <--Bad
#     bytes_received = receive_until(input, sizeof(input), '\n');   <--Good
#
# Methodology:
# 1. Find gets instruction
# 2. There's a vulnerability
#
# Try it on: REMATCH_1--Hat_Trick--Morris_Worm
#
#============================================================================================================

import sys
import grakn

def main(keyspace):
    client = grakn.Grakn(uri='localhost:48555')
    with client.session(keyspace=keyspace).transaction(grakn.TxType.READ) as graph:
        # Check for gets() function
        # Get address of function to use for next query
        func_names = ['gets', 'cgc_gets']
        func_addrs = []
        for function_name in func_names:
            query1 = 'match $func isa function, has func-name "{}", has asm-address $a; get $a;'.format(function_name)
            func_addrs += [int(result.value(), 16) for result in graph.query(query1).collect_concepts()]
        
        # If the function is found continue query
        for func_addr in func_addrs:
            # Get all instructions that have function name
            query2 = 'match $x has operation-type "MLIL_CALL_SSA" has asm-address $a; $y isa"MLIL_CONST_PTR"; ($x,$y); $z isa constant, has constant-value {}; ($y,$z); get $a;'.format(func_addr)
            result2 = graph.query(query2).collect_concepts()

            # If there are instructions that use the function check the instructions
            for instr in result2:
                ins_addr = instr.value()
                print("CWE-120: Buffer Copy Without Checking Size of Input at {}".format(ins_addr))

if __name__ == "__main__":
    if len(sys.argv) > 1:
        keyspace = sys.argv[1]
    else:
        keyspace = "grakn"
    main(keyspace)
