## Grakn JSON migration template for binja_mlil_ssa.gql : link instructions to their basic-blocks

## Loop over all functions in the binary
for(<functions>) do {

    ## Loop over all basic-blocks in this function and link basic-blocks to the function they are in
    for(<basic_blocks>) do {

        ## Loop over all instructions in this basic-block, add them, and link them to their basic-block
        ## in_bb is a resource of 'instruction' that helps locate a basic-block by it's hash name
        for(<instructions>) do {
            match

            $bb isa basic-block
                has bb-name <in_bb>;

            $ins isa instruction
                has name <name>;

            insert
            (contains-instruction: $ins, in-basic-block: $bb) isa has-instruction;
        }
    }
}
