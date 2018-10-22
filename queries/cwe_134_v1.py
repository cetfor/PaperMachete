#============================================================================================================
# CWE-134 Uncontrolled Format String
#
# Vuln Info: This vulnerability comes from using printf without a modifier
# Ex: cgc_printf(message);          <--Bad
#     cgc_printf("%s", message);    <--Good
#
# Methodology:
# 1. Check if file has a printf function
# 2. Check if any instructions use printf
# 3. Check if params in printf are data type(correct) or var_type(incorrect, no modifier i.e. %s used)
#
# Try it on: Barcoder, Checkmate, Kaprica_Go
#============================================================================================================

import sys
import grakn

def main(keyspace):
    client = grakn.Grakn(uri='localhost:48555')
    with client.session(keyspace=keyspace).transaction(grakn.TxType.READ) as graph:

        # Get address of printf to use for next query
        query1 ='match $func isa function, has func-name contains "printf", has asm-address $a; offset 0; limit 100; get $a;'
        result1 = [result.map() for result in graph.query(query1)]
        if len(result1) > 0:
            print("Found potential calls at the following addresses:")
            for addr in result1:
                print(addr['a'].value())

        # If printf is found continue query
        for printf_func in result1:
            # Pull any instructions that use printf and don't use a modifier (have var type and not data type)
            func_addr = int(printf_func['a'].value(), 16)
            print("Scanning address {}".format(hex(func_addr)))
            query2 = 'match $x isa instruction, has operation-type "MLIL_CALL_SSA", has asm-address $a; $y isa "MLIL_CONST_PTR"; ($x,$y); $z isa constant, has constant-value {}; ($y,$z); $l isa list, has list-size 1; ($x,$l); $s isa "MLIL_VAR_SSA"; ($l,$s); offset 0; limit 500; get $x, $a;'.format(func_addr)
            result2 = [result.map() for result in graph.query(query2)]

            # If there is an instruction that uses printf without modifier, output instruction
            if result2:
                for instr in result2:
                    asm_addr = instr['a'].value()
                    print("CWE-134: Uncontrolled Format String possible at {} ".format(asm_addr))

if __name__ == "__main__":
    if len(sys.argv) > 1:
        keyspace = sys.argv[1]
        main(keyspace)
    else:
        print("Please specify a keyspace to search.\nUsage: python3.6 {} <keyspace>".format(sys.argv[0]))

