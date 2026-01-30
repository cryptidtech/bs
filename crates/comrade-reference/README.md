# Comrade Verification Runtime -  Reference Implementation

An opinionated script runtime for lock and unlock scripts. Since scripts are just plain text, they need to be executed "somewhere, somehow" and this can be done by various means. For example, in previous versions of Comrade, the Rhai scripting engine was used to execute the scripts. This could be done using other scripting languages such as Lua, but in this implementation, a domain specific language (DSL) parser is used to interpret and run the scripts.

## Script Runtime & Script Parser

This crate contains the parser, abstract syntax tree, and runtime to execute the scripts. In this implementation, a simple Domain Specific Language (DSL) parser is written in [pest](https://pest.rs/book/intro.html), and then the abstract syntax tree is executed against corresponding Rust functions. In other words, when `check_signature(..)` appears in a script, the runtime calls the `check_signature` cryptographic construct in Rust to evaluate whether the script is valid or not.

## Comrade Crypto Constructs

This implementation calls associated cryptographic constructs to verify the validity of the scripts against each other. This is the reference implementation for the [comrade](../comrade) and [comrade-component](../comrade-component).

If different cryptographic primitives are desired, the crypto dependencies can be changed for new ones, a new component built, and run with bettersign.

## Design Considerations 

This comrade architecture was chosen to give users maximum flexibility, upgradeability, and extensibility of the backend. Because of the modular approach, backends can be switched out without impacting the rest of the system. This makes open source more viable and maintainable, since components can be used interchangeably without placing the entire maintenance burden on a single user.
