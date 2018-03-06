## Grakn JSON migration template for binja_mlil_ssa.gql : inserts basic-blocks

## Loop over all functions in the binary
for(<functions>) do {
    match
    $f isa function
        has func-name <func_name>
        has asm-address <asm_addr>;
        
    ## Loop over all basic-blocks in this function and link basic-blocks to the function they are in
    insert
    for(<basic_blocks>) do {
        $<bb_name> isa basic-block
            has bb-name <bb_name>
            has bb-start <bb_start>
            has bb-end <bb_end>;
        (contains-basic-block: $<bb_name>, in-function: $f) isa has-basic-block;
    }
}
