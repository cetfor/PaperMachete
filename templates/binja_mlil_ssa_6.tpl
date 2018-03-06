## Grakn JSON migration template for binja_mlil_ssa.gql : inserts instruction nodes (AST nodes)

## Loop over all functions in the binary
for(<functions>) do {

    ## Loop over all basic-blocks in this function and link basic-blocks to the function they are in
    for(<basic_blocks>) do {

        ## Loop over all instructions in this basic-block, add them, and link them to their basic-block
        for(<instructions>) do {
            
            ## Loop over all nodes in this instruction and add them
            for(<nodes>) do {
                insert
                ## list nodes
                if (@equals(<node_type>, "list")) do {
                    $<name> isa <node_type>
                        has name <name>
                        has parent-hash <parent_hash>
                        has edge-label <edge_label>
                        has list-size <list_size>;
                }

                ## constant nodes
                elseif (@equals(<node_type>, "constant")) do {
                    $<name> isa <node_type>
                        has name <name>
                        has parent-hash <parent_hash>
                        has edge-label <edge_label>
                        has constant-value <constant_value>;
                }

                ## variable-ssa nodes
                elseif (@equals(<node_type>, "variable-ssa")) do {
                    $<name> isa <node_type>
                        has name <name>
                        has parent-hash <parent_hash>
                        has edge-label <edge_label>
                        has var <var>
                        has version <version>
                        has var-type <var_type>
                        has var-size <var_size>
                        has var-func <var_func>;
                }

                ## variable nodes
                elseif (@equals(<node_type>, "variable")) do {
                    $<name> isa <node_type>
                        has name <name>
                        has parent-hash <parent_hash>
                        has edge-label <edge_label>
                        has var <var>
                        has var-type <var_type>
                        has var-size <var_size>
                        has var-func <var_func>;
                }

                ## all other nodes (operations)
                else {
                    $<name> isa <node_type>
                        has name <name>
                        has parent-hash <parent_hash>
                        has edge-label <edge_label>;
                }
            }
        }
    }
}
