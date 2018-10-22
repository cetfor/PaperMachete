#============================================================================================================
# CWE-129:Imporper validation of array index
#
# Vuln Info: This vulnerability comes from using untrusted (unchecked) input when using an array index.
#
# Methodology: Find all signed comparisons of a varaible and constant and follow the variable to see if its
#               other bound is checked.
#
# TODO: Currently the script searches out all comparisons to see if the other bound is checked by looking
#       for the same variable in other comparisons. The search can be improved by instead searching for where
#       the user can modify an array index then checking for bounds on that.
#
# Limitations: This implementation only find instances where one bound was checked, but not the other.
#               Also this implementation does not specifically search for array indexs, but comparisons in general.
#
# try it on: recipe_and_pantry_manager
#============================================================================================================

import sys
import grakn

#Exits the script
def fail():
    sys.exit()

#Finds comparisons that are acting as a lower boudns check
def lowerCheck():
    query = 'match {$comp isa MLIL_CMP_SGE;} or {$comp isa MLIL_CMP_SGT;};$node isa MLIL_VAR_SSA;$cons isa MLIL_CONST;($comp, $node);($comp, $cons);$varssa isa variable-ssa has var $var;($node, $varssa);get $comp, $var;'
    return [result.map() for result in graph.query(query)]

#Finds comparisons that are acting as an upper bounds check
def upperCheck():
    query = 'match {$comp isa MLIL_CMP_SLE;} or {$comp isa MLIL_CMP_SLT;};$node isa MLIL_VAR_SSA;$cons isa MLIL_CONST;($comp, $node);($comp, $cons);$varssa isa variable-ssa has var $var;($node, $varssa);get $comp, $var;'
    return [result.map() for result in graph.query(query)]

#Returns the addresss of a comparison instruction
def get_addr(comp):
    query = 'match $comp id "' + comp  + '";$inst isa instruction, has asm-address $addr;($comp, $inst);get $addr;'
    return [result.map() for result in graph.query(query)]

def main(keyspace):
    client = grakn.Grakn(uri='localhost:48555')
    global graph
    with client.session(keyspace=keyspace).transaction(grakn.TxType.READ) as graph:

        #Find a variable being compared
        query1 = 'match {$comp isa MLIL_CMP_SGE;} or {$comp isa MLIL_CMP_SLE;} or {$comp isa MLIL_CMP_SLT;} or {$comp isa MLIL_CMP_SGT;};$node isa MLIL_VAR_SSA;$cons isa MLIL_CONST;($comp, $node);($comp, $cons);$varssa isa variable-ssa has var $var;($node, $varssa);get $comp, $var;'
        result1 = [result.map() for result in graph.query(query1)]

        #Parse the output of result1 into the compare statements and varaible names
        comp, var = [], []
        if result1:
            for entry in result1:
                comp.append(entry['comp'].id)
                var.append(entry['var'].value())
        else:
            fail()
        for entry in comp:
            #Do upper bound check
            if ('SGE' or 'SGT') in entry:
                lower = lowerCheck()
                if lower:
                    for item in lower:
                        if item['var'].value() not in var:
                            #failed to find upper bound check
                            addr = get_addr(entry)
                            print('CWE-129: Missing upper bound check at ' + str(addr[0]['addr'].value()))
                        else:
                            adddr = get_addr(entry)
                else:
                    addr = get_addr(entry)
                    print('CWE-129: Missing upper bound check at ' + str(addr[0]['addr'].value()))
            #Do lower bound check
            else:
                upper = upperCheck()
                if upper:
                    for item in upper:
                        if item['var'].value() not in var:
                            #failed to find lower bound check
                            addr = get_addr(entry)
                            print('CWE-129: Missing lower bound check at ' + str(addr[0]['addr'].value()))
                        else:
                            addr = get_addr(entry)
                else:
                    addr = get_addr(entry)
                    print('CWE-129: Missing lower bound check at ' + str(addr[0]['addr'].value()))

if __name__ == "__main__":
    if len(sys.argv) > 1:
        keyspace = sys.argv[1]
    else:
        keyspace = "grakn"
    main(keyspace)
