#=======================================================================================
# CWE-788: Access of Memory Location After End of Buffer
#
# Vuln Info: The software reads or writes to a buffer using an index or pointer that
#            references a memory location after the end of the buffer.
#
# Methodology:
# 1.Find any arrays
# 2.Find indexing variables for said arrays
# 3.Look to see if those variables are used in a comparison (bounds check)
#=======================================================================================

import sys
import grakn

#Exits script
def fail():
    return 0
    sys.exit()

#Searches for potential array declarations
def query1():
    query = 'match $set isa instruction, has operation-type "MLIL_SET_VAR_SSA";$ptr isa MLIL_CONST_PTR;($set, $ptr);$reg isa variable-ssa, has var $index;($set, $reg); get $index;'
    return [result.map() for result in graph.query(query)]

#Finds potential loops
def query2():
    query = 'match $block isa basic-block;($block, $inst);$inst isa instruction;$reg isa variable-ssa, has var $index, has edge-label "dest";($inst, $reg);get $index, $block;'
    return [result.map() for result in graph.query(query)]

#Checks query2 for if statements
def query3(item):
    query = 'match $block isa basic-block, id "' + item  + '";($block, $inst);$inst isa instruction, has operation-type "MLIL_IF";offset 0; get $inst;'
    return [result.map() for result in graph.query(query)]

#Finds and returns various information about the loops, including the counting variable
def query4(entry):
    query = 'match $block isa basic-block, id "' + entry  + '";($block, contains-instruction:$inst);$inst isa instruction, has operation-type "MLIL_SET_VAR_SSA";($inst, to-node:$add);$add isa MLIL_ADD;$var isa MLIL_VAR_SSA;($add, $var);$const isa MLIL_CONST;($add, $const);$one isa constant has constant-value 1;($const, $one);$reg isa variable-ssa, has var $index, has version $version, has edge-label "dest";($inst, $reg);get $index, $reg, $version;'
    return [result.map() for result in graph.query(query)]

#Checks if the bounds on the counting varaible (array index) are ever checked
def query5():
    query = 'match $block isa basic-block;$inst isa instruction, has operation-type "MLIL_IF";($block, $inst);{$comp isa MLIL_CMP_SGE;} or {$comp isa MLIL_CMP_SLE;} or {$comp isa MLIL_CMP_SLT;} or {$comp isa MLIL_CMP_SGT;} or {$comp isa MLIL_CMP_UGE;} or {$comp isa MLIL_CMP_ULE;} or {$comp isa MLIL_CMP_ULT;} or {$comp isa MLIL_CMP_UGT;};($inst, $comp);$reg isa MLIL_VAR_SSA;($comp, $reg);$index isa variable-ssa, has var $var, has version $version;($reg, $index);get $var, $version;'
    return [result.map() for result in graph.query(query)]

#Returns asm-address of vulnerability
def query6(reg_type, reg):
    query = 'match $inst isa instruction, has asm-address $adr;$var isa '+ reg_type + ', id "' + reg + '";($inst, $var);get $adr;'
    return [result.map() for result in graph.query(query)]

def main(keyspace):
    client = grakn.Grakn(uri='localhost:48555')
    global graph
    with client.session(keyspace=keyspace).transaction(grakn.TxType.READ) as graph:

        # Find possible arrays
        array = []
        q1 = query1()
        if q1:
            i = 0
            for item in q1:
                array.append(q1[i]['index'].id)
                i += 1
        else:
            fail()

        # Find loops involving the array
        block = []
        q2 = query2()
        if q2:
            i = 0
            for item in q2:
                if q2[i]['index'].id in array:
                    block.append(q2[i]['block'].id)
                i += 1
        else:
            fail()

        # Do the 'loop' blocks contain if statements?
        if_id = []
        block2 = block.copy()
        for item in block2:
            q3 = query3(item)
            if not q3:
                block.remove(item)

        # Find the loop counters
        var, version, var_id, reg, reg_type, block2 = [], [], [], [], [], block.copy()
        for entry in block2:
            q4 = query4(entry)
            if q4:
                i = 0
                for item in q4:
                    reg.append(item['reg'].id)
                    reg_type.append(item['reg'].type().label())
                    var.append(item['index'].value())
                    version.append(item['version'].value())
                    var_id.append(item['index'].id)
                    i += 1
            else:
                block.remove(entry)
        i = len(var) - 1

        # Find is the bounds of the loop counter are checked
        var2 = []
        q5 = query5()
        i = 0
        for entry in q5:
            var2.append(q5[i]['var'].value())
            i += 1

        # Any variables in var[] but not var2[] are potential vulnerabilities
        i = 0
        for entry in var:
            if entry not in var2:
                q6 = query6(reg_type[i], reg[i])
                print('CWE-788: Array index missing bounds check at ' + q6[0]['adr'].value() + ' associated with '+ var[i] + '#' + str(version[i]) + ' id = ' + var_id[i] + ' sub of ' + reg_type[i] + ' id = ' + reg[i])
            i += 1

if __name__ == "__main__":
    if len(sys.argv) > 1:
        keyspace = sys.argv[1]
    else:
        keyspace = "grakn"
    main(keyspace)
