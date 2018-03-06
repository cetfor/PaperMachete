## Grakn JSON migration template for binja_mlil_ssa.gql : inserts functions

## Loop over all functions in the binary
for(<functions>) do {
	insert
    $f isa function
        has func-name <func_name>
        has asm-address <asm_addr>;
}
