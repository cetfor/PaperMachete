## Grakn JSON migration template for binja_mlil_ssa.gql : links instruction nodes (AST nodes)

## Loop over all functions in the binary
for(<functions>) do {

    ## Loop over all basic-blocks in this function and link basic-blocks to the function they are in
    for(<basic_blocks>) do {

        ## Loop over all instructions in this basic-block, add them, and link them to their basic-block
        for(<instructions>) do {

            ## Loop over all nodes in this instruction and add them
            for(<nodes>) do {
                match
                $<parent_hash> isa entity
                    has name <parent_hash>;
                $<name> isa entity
                    has name <name>;
                
                insert
                (from-node: $<parent_hash>, to-node: $<name>) isa node-link;
            }
        }
    }
}
