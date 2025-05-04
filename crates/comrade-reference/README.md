# Comrade Verification Runtime -  Reference Implementation

An opinionated script runtime for lock and unlcok scripts. Since scripts are just plain text, they need to be run "somewhere, somehow" and this can be by various means. For example, in previous versions of Comrade the Rhai scripting engine was used to execute the scripts. This could be done using other scripting languages such as Lua, but in this implementation a domain specific language (DSL) parser is used to run the scripts.

## Script Runtime & Script Parser

This crate contains the parser, abstract syntax tree, and runtime to execute the scripts.  In this implementation, a simple Domain Specific Language (DSL) parser is written in pest, and then the abstract syntax tree executed against their corresponding Rust functions. In other words, `check_signature(..)` in plog script runs `check_signature` Cryptographic construct to evaluate the script to check whether it's valid or not.

## Comrade Crypto Constructs

This calls associated cryptographic constructs to verify the validity of the scripts against each other. This is the reference implementation for the comrade-component.

If different primiatives are desired, the crypto dependencies can be changed for new ones, a new component built, and run with bettersign.

## Design Considerations 

This comrade architecture was chosen to give users manximum flexibility, upgradeability and extensibility of the backend. Because of the modular approach, backends can be switched out without impacting the rest of the system. This makes open source more viable and maintainable, since parts can be used interchangeably without placing all the burden on the user to maintain the entire system.
