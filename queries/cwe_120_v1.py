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
    graph = grakn.Client(uri='http://localhost:4567', keyspace=keyspace)

    # Check for gets() function
    # Get address of function to use for next query
    function_name = 'gets'
    query1 = 'match $func isa function, has func-name contains "{}", has asm-address $a; get $a;'.format(function_name)
    result1 = graph.execute(query1)
    
    # If the function is found continue query
    if result1: 
        # Get all instructions that have function name
        func_addr = int(result1[0]['a']['value'], 16)
        query2 = 'match $x has operation-type "MLIL_CALL_SSA" has asm-address $a; $y isa"MLIL_CONST_PTR"; ($x,$y); $z isa constant, has constant-value {}; ($y,$z); get $x, $a;'.format(func_addr)
        result2 = graph.execute(query2)
        
        # If there are instructions that use the function check the instructions 
        for instr in result2:
            ins_addr = instr['a']['value']
            print("CWE-120: Buffer Copy Without Checking Size of Input at {}\n".format(ins_addr))

if __name__ == "__main__":
    if len(sys.argv) > 1:
        keyspace = sys.argv[1]
    else:
        keyspace = "grakn"
    main(keyspace)
