# Comrade Cryptographic Constructs

These are the crypto constructs used when building the reference implementation of the comrade-component.

If different primiatives are desired, these dependencies can be changed for new ones, a new component built, and run with bettersign.

This crate also contains the parser, abstract syntax tree, and runtime to execute the scripts. Since scripts are plain text, they need to be run "somewhere, somehow" and this can be by various means. For example, in previous versions of Comrade the Rhai scripting engine was used to execute the scripts. In this implementation, a simple Domain Specific Language (DSL) parser is written in pest, and then the abstract syntax tree executed against their corresponding Rust functions. In other words, `check_signature(..)` in plog script runs `check_signature` Cryptographic construct to evaluate the script to check whether it's valid or not.


