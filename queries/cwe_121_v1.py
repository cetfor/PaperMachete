#============================================================================================================
# CWE-121: Stack-based Buffer Overflow
#
# Vuln Info: This vulnerability comes from allocating too much space for a string.
# Ex: char string[64]
#     (cgc_receive_delim(0, string, 128, '\n') != 0)                <--Bad
#     (cgc_receive_delim(0, string, sizeof(string), '\n') != 0)     <--Good
#
# Methodo#logy:
# 1. Find all instructions that call a specific function specified with function_name
# 2. Check these instructions' parameters, string, and bytes allocated (sizeof(string))
# 3. Find where the string was initialized to get amount of bytes allocated
# 4. If the amount of bytes allocated != size of string alert possible vulerability
#
# Try it on: Palindrome2, ShoutCTF
#
# Includes functions:
# fgets(name, sizeof(name), stdin)
# receive_delim(0, 0, string, sizeof(string), '\n')
# strncpy(targetBuffer, srcBuffer, sizeof(targetBuffer));
# receive_until(buff, '\n', 25);
# memcpy(str1, str2, n);
# freaduntil(buf, sizeof(buf), '\n', stdin)
# read(int fd, void *buf, size_t count);
#============================================================================================================

import sys
import grakn

def main(keyspace):
    client = grakn.Grakn(uri='localhost:48555')
    with client.session(keyspace=keyspace).transaction(grakn.TxType.READ) as graph:

        # Functions with indexes for (dest, sizeof(dest)) stored in dict
        functions = {"receive_delim": (2,3), "fgets": (0,1), "strncpy": (0,2), "receive_until": (0,2), "memcpy": (0,2), "freaduntil": (1,2), "read":(1,2)}

        # Check for potential vuln in each function
        for function_name in functions:
        # Get address of function to use for next query
            query1 = 'match $func isa function, has func-name contains "{}", has asm-address $a; get $a;'.format(function_name)
            result1 = [result.map() for result in graph.query(query1)]

            # If the function is found continue query
            if result1:
                # Get all instructions that have function name
                func_addr = int(result1[0]['a'].value(), 16)
                query2 = 'match $x has operation-type "MLIL_CALL_SSA"; $y isa"MLIL_CONST_PTR"; ($x,$y); $z isa constant, has constant-value {}; ($y,$z); get $x;'.format(func_addr)
                result2 = [result.map() for result in graph.query(query2)]

                # If there are instructions that use the function check the instructions
                if result2:

                    buff_index = functions[function_name][0]
                    size_index = functions[function_name][1]
                    for instr in result2:
                        Id = instr['x'].id
                        query3 = 'match $x id "' + Id + '"; $l isa list; ($x,$l); (from-node: $l, $q); $q has edge-label $e; (from-node: $q, $v); {$v has var $s;} or {$v has constant-value $s;}; get $e, $s;'
                        result3 = [result.map() for result in graph.query(query3)]

                        # This section grabs instrution params and insert into an array
                        param_array = [0, 0, 0, 0, 0, 0, 0, 0]

                        for ele in result3:
                            index = int(ele['e'].value())
                            val = ele['s'].value()
                            param_array[index] = val
                        # Get var name - This is done to determine how many bytes the variable is
                        var_name = param_array[buff_index]
                        var_name = var_name.split('#',1)[0].lstrip()

                        # NOTE Enhancement Make finding buff_size the same as string_size
                        # This assumes that buffer_size is a number, breaks when its a var or register
                        # Get buffer size
                        try:
                            buff_size = int(param_array[size_index])
                        except ValueError as err:
                            continue
                        # Get size of string in by finding initialization Ex. var_88 = &var_58
                        # Find where string is initialzed
                        query4 = 'match $x id "{}"; $y isa basic-block; ($x,$y); $z isa instruction, has operation-type "MLIL_SET_VAR_SSA"; ($y,$z); {{$v1 isa variable, has var "{}";}} or {{$v1 isa variable-ssa, has var "{}";}}; ($z, $v1); $w isa MLIL_ADDRESS_OF; ($w, $z); $v isa variable, has var-size $s; ($w, $v); get $s, $x;'.format(Id, var_name, var_name)
                        result4 = [result.map() for result in graph.query(query4)]

                        if (result4):
                            string_size = result4[0]['s'].value()
                            # Finally Determine if buffer size == sizeof(str)
                            if string_size != buff_size:
                                instruction_ID = result4[0]['x'].id
                                query5 = 'match $i id {}, has asm-address $a; get $a;'.format(instruction_ID)
                                result5 = [result.map() for result in graph.query(query5)]
                                instr_addr = result5[0]['a'].value()

                                print("CWE-121: Stack-based Overflow possible at {}".format(instr_addr))

if __name__ == "__main__":
    if len(sys.argv) > 1:
        keyspace = sys.argv[1]
    else:
        keyspace = "grakn"
    main(keyspace)
