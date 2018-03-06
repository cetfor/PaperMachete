## Grakn JSON migration template for binja_mlil_ssa.gql : links basic-blocks

## Loop over all functions in the binary
for(<functions>) do {
            
    ## Now loop over bb-edges and link the source and target basic-blocks in this function
    for(<bb_edges>) do {
        match 
        $<source> isa basic-block
            has bb-name <source>;
        $<target> isa basic-block
            has bb-name <target>;   
        
        insert
        (from-basic-block: $<source>, to-basic-block: $<target>) isa basic-block-edge;
    }
}
