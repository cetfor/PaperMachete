import sys
import json
from struct import pack, unpack
from os.path import basename, join, isfile
from operator import attrgetter
from collections import defaultdict
import binaryninja as binja

PM = None
vars_and_sizes = {}

class PaperMachete():
    def __init__(self):
        self.functions = []

class PMFunction(): 
    def __init__(self, func_name, asm_addr):
        self.func_name = func_name
        self.asm_addr = asm_addr
        self.basic_blocks = []
        self.bb_edges = []

class PMBasicBlock():
    def __init__(self, bb_name, bb_start, bb_end):
        self.bb_name = bb_name
        self.bb_start = bb_start
        self.bb_end = bb_end - 1 # set end as last il index (not +1 like binja gives us)
        self.instructions = []

class PMInstruction():
    def __init__(self, name, il_index, asm_address, operation_type, in_bb):
        self.name = name
        self.il_index = il_index
        self.asm_address = asm_address
        self.operation_type = operation_type
        self.in_bb = in_bb
        self.nodes = []

class PMOperation():
    def __init__(self, name, depth, node_type, edge_label, parent_hash):
        self.name = name
        self.depth = depth
        self.node_type = node_type
        self.edge_label = edge_label
        self.parent_hash = parent_hash

class PMNodeList():
    def __init__(self, name, depth, node_type, edge_label, parent_hash, list_size):
        self.name = name
        self.depth = depth
        self.node_type = node_type
        self.edge_label = edge_label
        self.parent_hash = parent_hash
        self.list_size = list_size

class PMEndNodeConstant():
    def __init__(self, name, depth, node_type, edge_label, parent_hash, constant_value):
        self.name = name
        self.depth = depth
        self.node_type = node_type
        self.edge_label = edge_label
        self.parent_hash = parent_hash
        self.constant_value = constant_value

class PMEndNodeVarSSA():
    def __init__(self, name, depth, node_type, edge_label, parent_hash, var, version, var_type, var_size, var_func):
        self.name = name
        self.depth = depth
        self.node_type = node_type
        self.edge_label = edge_label
        self.parent_hash = parent_hash
        self.var = var
        self.version = version
        self.var_type = var_type
        self.var_size = var_size
        self.var_func = var_func

class PMEndNodeVariable():
    def __init__(self, name, depth, node_type, edge_label, parent_hash, var, var_type, var_size, var_func):
        self.name = name
        self.depth = depth
        self.node_type = node_type
        self.edge_label = edge_label
        self.parent_hash = parent_hash
        self.var = var
        self.var_type = var_type
        self.var_size = var_size
        self.var_func = var_func

class PMBBEdge():
    def __init__(self, source, target):
        self.source = source
        self.target = target


def process_function(func):
    global insn_list
    global vars_and_sizes

    insn_list = []
    vars_and_sizes = {}

    stack = str(binja.function.Function.stack_layout.__get__(func))
    vars_and_sizes = get_variable_sizes(stack)

    func_name = func.name.replace('.', '_')
    asm_addr = hex(func.start).strip('L')

    PM.functions.append(PMFunction(func_name, asm_addr))


def process_basic_block(func, block):
    func_name = func.name.replace('.', '_')
    bb_name = "bb_{}_{}_{}".format(block.start, block.end-1, func_name)

    for func in PM.functions:
        if func.func_name == func_name:
            func.basic_blocks.append(PMBasicBlock(bb_name, block.start, block.end))


def process_instruction(func, block, insn):
    global insn_list

    func_name = func.name.replace('.', '_')

    # A single ISA instruction can map to many IL instructions.
    # This can cause the same instruction to be processed many times.
    # To avoid this, we track instructions in a function and only
    # process them once. We clear this global list in process_function().

    # To complicate this more, MLIL_GOTO operations always seem to have
    # address => 0x0. So we have to process 0x0 addresses multiple times until
    # this behavior changes in Binary Ninja (this may actually be expected).
    
    if (insn.address not in insn_list) or (insn.address == 0x0):
        ast_parse([func, block, insn])
        insn_list.append(insn.address)

    # sort the 'nodes' list in each instruction by 'depth'
    # This is extremely important for Grakn's migration template
    # since nodes at depth 1 need to exist before nodes at depth
    # 2 can be linked to them (and so on).
    
    for func in PM.functions:
        for bb in func.basic_blocks:
            for inst in bb.instructions:
                (inst.nodes).sort(key=attrgetter('depth'))


def ast_build_json(args, name, il, level=0, edge=""):
    global insn_list
    global vars_and_sizes

    func  = args[0]
    block = args[1]
    insn  = args[2]

    func_name = func.name.replace('.', '_')

    # slice off the last "_#" and rejoin to get the parent reference hash
    parent = "_".join(name.split('_')[:-1])

    # Hashes of instruction nodes in the AST look like: "N_8735918103813_4195908"
    # One element down from an instruction will look like: "N_8735918103813_4195908_0"
    # So if there are two "_" in the hash, the node is an instruction. List nodes have
    # the letter 'L' appended to them. (Yeah, I LOL'd when I wrote this too.)
    depth = name.count("_") - 2
    if 'L' in parent:
        parent_type = "list"
        name = name.replace('L', 'N') # reset node status
    elif parent.count("_") == 2:
        parent_type = "instruction"
    else:
        parent_type = "operation"

    # get the instruction hash this node belongs in
    inst_hash = "_".join(name.split('_')[:3])

    # get the basic-block this node belongs in
    inbb = "bb_{}_{}_{}".format(block.start, block.end-1, func_name)

    if isinstance(il, binja.MediumLevelILInstruction):

        # instruction
        if level == 0:
            il_index =  il.instr_index
            asm_address = hex(il.address).strip('L')
            operation_type = str(il.operation).split('.')[1]

            for func in PM.functions:
                for bb in func.basic_blocks:
                    if bb.bb_name == inbb:
                        # This next if statement is to avoid issues with MLIL_GOTO nodes
                        # being placed in the wrong basic blocks. This is because all MLIL_GOTO
                        # nodes have and asm_address of 0x0, so we leave them out of the insn_list global.
                        # This also means, the same instruction can be added twice! So we need to check if
                        # the same node already exists. If it does, we don't add it.
                        if il_index >= bb.bb_start and il_index <= bb.bb_end:
                            if operation_type == "MLIL_GOTO":
                                if (inst_hash not in insn_list):
                                    insn_list.append(inst_hash)
                                else:
                                    continue # don't add this again!
                            bb.instructions.append(PMInstruction(inst_hash, il_index, asm_address, operation_type, inbb))
                            
        # operation
        else:
            node_type = str(il.operation).split('.')[1]
            edge_label = str(edge)
            parent_hash = parent

            for func in PM.functions:
                for bb in func.basic_blocks:
                    for inst in bb.instructions:
                        if inst.name == inst_hash:
                            inst.nodes.append(PMOperation(name, depth, node_type, edge_label, parent_hash))
                            
        # edge
        for i, o in enumerate(il.operands):
            try:
                edge_label = str(il.ILOperations[il.operation][i][0])
            except IndexError:
                # Addresses issue in binja v1.1 stable with MLIL_SET_VAR_ALIASED 
                # operations in the Python bindings. 
                # See: https://github.com/Vector35/binaryninja-api/issues/787 
                edge_label = "unimplemented"
            child_name = "{}_{}".format(name, i)
            ast_build_json(args, child_name, o, level+1, edge_label)
            

    # list of operands / nodes
    elif isinstance(il, list):
        node_type = "list"
        edge_label = str(edge)
        parent_hash = parent
        name = name.replace('N', 'L') # list hashes have an 'L' prefix to distinguish from nodes ('N').
        list_size = len(il)

        for func in PM.functions:
            for bb in func.basic_blocks:
                for inst in bb.instructions:
                    if inst.name == inst_hash:
                        inst.nodes.append(PMNodeList(name, depth, node_type, edge_label, parent_hash, list_size))
                        

        # add elements from 
        for i, item in enumerate(il):
            edge_label = str(i)
            item_name = "{}_{}".format(name, i)
            ast_build_json(args, item_name, item, level+1, edge_label)
            
    # end node
    else:
        parent_hash = parent
        edge_label = str(edge)

        # constant
        if isinstance(il, long):
            node_type = "constant"
            constant_value = str(il)

            for func in PM.functions:
                for bb in func.basic_blocks:
                    for inst in bb.instructions:
                        if inst.name == inst_hash:
                            inst.nodes.append(PMEndNodeConstant(name, depth, node_type, edge_label, parent_hash, constant_value))


        # SSAVariable (not using type information)
        elif isinstance(il, binja.mediumlevelil.SSAVariable):
            node_type = "variable-ssa"
            var = str(il.var)
            version = il.version

            var_type = str(il.var.type)
            var_size = vars_and_sizes.get(str(il.var), 4) 
            var_func = func_name

            for func in PM.functions:
                for bb in func.basic_blocks:
                    for inst in bb.instructions:
                        if inst.name == inst_hash:
                            inst.nodes.append(PMEndNodeVarSSA(name, depth, node_type, edge_label, parent_hash, var, version, var_type, var_size, var_func))


        # Variable (contains more information than we currently use)
        elif isinstance(il, binja.function.Variable):
            node_type = "variable"
            var = str(il)

            var_type = str(il.type)
            var_size = vars_and_sizes.get(str(il), 4) 
            var_func = func_name

            for func in PM.functions:
                for bb in func.basic_blocks:
                    for inst in bb.instructions:
                        if inst.name == inst_hash:
                            inst.nodes.append(PMEndNodeVariable(name, depth, node_type, edge_label, parent_hash, var, var_type, var_size, var_func))


        # Unknown terminating node (this should not be reached)
        else:
            print "A terminating node was encountered that was not expected: '{}'".format(type(il))
            raise ValueError


def ast_name_element(args, il_type, il):
    h = hash(il)
    name = "N_{}_{}".format(h, il.address)
    ast_build_json(args, name, il)


def ast_parse(args):
    func = args[0]
    block = args[1]
    insn = args[2]

    print "  function: {} (asm-addr: {})".format(func.name, hex(insn.address).strip('L'))
    lookup = defaultdict(lambda: defaultdict(list))

    for block in func.medium_level_il.ssa_form:
        for mil in block:
            lookup['MediumLevelILSSA'][mil.address].append(mil)

    for il_type in sorted(lookup):
        ils = lookup[il_type][insn.address]
        for il in sorted(ils):
            ast_name_element(args, il_type, il)


def process_edges(func):
    func_name = (func.name).replace('.', '_')

    for block in func.medium_level_il.ssa_form:
        if len(block.outgoing_edges) > 0:
            for edge in block.outgoing_edges:
                source = "bb_{}_{}_{}".format(edge.source.start, edge.source.end-1, func_name)
                target = "bb_{}_{}_{}".format(edge.target.start, edge.target.end-1, func_name)
                for func in PM.functions:
                    if func.func_name == func_name:
                        func.bb_edges.append(PMBBEdge(source, target))


def get_offset_from_var(var):
    """
    Helper for get_variable_sizes)_
    Use this to calculate var offset. 
        e.g. var_90, __saved_edi --> 144, -1
    """
    instance = False
    i=0

    # Parse string
    i = var.rfind(' ')+1
    tmp = var[i:-1]

    # Parse var
    if tmp[0] == 'v':
        tmp = tmp[4:]
        j = tmp.find('_')

        # Handles SSA var instances (var_14_1) and converts c, 58, 88 --> 12, 88, 136
        if (j != -1):
            tmp = tmp[:j]
            instance = True
        else:
            instance = False

    try:    
        tmp = int(tmp, 16)
    except:
        tmp = -1

    # -1 for non vars
    else:
        tmp = -1
    
    return tmp, instance 


def get_variable_sizes(stack):
    """
    Called from process_function. This function Accepts a string 
    of stack variables and returns a dict of var names and sizes.
    """
    prev_offset = 0
    offset = 0
    counter = 0
    i=0
    var_dict = {}
    str_list = list(reversed(stack[1:-1].split(', ')))

    # Loop through each item on stack backwards
    for item in str_list:
        size=0
        tmp=0
        instance = False

        # Handle args and return addr
        if (('arg' in item) or ('return' in item)):
            size = 4

        elif('int32' in item):
            size = 4
            tmp, instance = get_offset_from_var(str_list[counter])
            if tmp != -1:
                offset = tmp
            if not instance:
                offset = prev_offset+4

        elif ('int64' in item):
            size = 8
            tmp, instance = get_offset_from_var(str_list[counter])
            if not instance:
                offset = prev_offset+8
            if tmp != -1:
                offset = tmp

        else:
            offset, instance = get_offset_from_var(str_list[counter])
            if instance:
                offset = offset-4

        if size == 0:  
            size = offset-prev_offset
        if (not instance):   
            prev_offset = offset

        # Parse string
        i = item.rfind(' ')+1
        key = item[i:-1]
        
        var_dict.update({key:size})
        counter = counter+1

    return var_dict


def analyze(bv, func_list=[]):

    list_len = len(func_list)

    ## process functions
    for func in bv.functions:
        if list_len > 0 and func.name not in func_list: continue
        process_function(func)

        ## process basic blocks
        for block in func.medium_level_il.ssa_form:
            process_basic_block(func, block)

            ## process instructions
            for insn in block:
                process_instruction(func, block, insn)

        ## process basic block edges
        # all edges need to exist in Grakn before we can do this
        # because edges stemming from loops wont have an associated
        # basic block inserted to create a relationship for.
        process_edges(func)


def main(target, func_list=[]):
    global PM

    PM = PaperMachete()
    
    if not isfile(target):
        print "The specified target '{}' is not a file. Try again.".format(target)
        return

    print "Invoking Binary Ninja and analyzing file: {}".format(target)
    bv = binja.BinaryViewType.get_view_of_file(target)
    bv.add_analysis_option('linearsweep')
    print "Performing linear sweep..."
    bv.update_analysis_and_wait()
    print "Linear sweep complete. Collecting BNIL data..."
    analyze(bv, func_list)
    
    # pretty printed json (pretty printed files are much larger than compact files!)
    target_json = json.dumps(PM, default=lambda o: o.__dict__, indent=4, sort_keys=True)
    
    # compact / minified json
    #target_json = json.dumps(PM, default=lambda o: o.__dict__)
    
    try:
        jf = None
        if __name__ == "__main__":
            jf = open("{}.json".format(basename(target)), "w")
        else:
            jf = open(join("analysis", "{}.json".format(basename(target))), "w")
        jf.write(target_json)
        jf.close()
    except IOError:
        print "ERROR: Unable to open/write to {}.json.".format(basename(target))
        return

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        func_list = sys.argv[2:]
    else:
        print "Usage: %s <binary> [function1 function2 ...]" % sys.argv[0]
    main(target, func_list)
