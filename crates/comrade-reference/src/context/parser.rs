// allow unused
#![allow(unused)]

use pest::iterators::{Pair, Pairs};
use pest::Parser;
use pest_derive::Parser;

use crate::error::ApiError;

#[derive(Parser)]
#[grammar = "context/parser/grammar.pest"]
pub struct ScriptParser;

/// Our AST defintion in Rust. Each function type is represented by an enum variant.
#[derive(Debug, Clone, PartialEq)]
pub enum Function<'a> {
    /// A function that checks the equality of a key.
    CheckEq(Key<'a>),
    /// A function that checks the signature of a key and message.
    CheckSignature(Key<'a>, &'a str),
    /// A function that checks the preimage of a key.
    CheckPreimage(Key<'a>),
    /// A function that pushes a path to the stack.
    Push(Key<'a>),
}

/// The [Function] Key can either be a String or the branch function which returns a String
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Key<'a> {
    String(&'a str),
    Branch(&'a str),
}

/// Represents a complete expression tree
#[derive(Debug, Clone, PartialEq)]
pub enum Expression<'a> {
    Function(Function<'a>),
    And(Box<Expression<'a>>, Box<Expression<'a>>),
    Or(Box<Expression<'a>>, Box<Expression<'a>>),
    Group(Box<Expression<'a>>),
}

/// Parse a script from a string into expressions
pub fn parse(script_str: &str) -> Result<Vec<Expression<'_>>, ApiError> {
    let pairs = ScriptParser::parse(Rule::script, script_str)
        .map_err(|e| ApiError::PestParse(Box::new(e)))?;

    let mut expressions = Vec::new();

    // Find the 'script' node
    for pair in pairs {
        if pair.as_rule() == Rule::script {
            // Process each expression within the script
            for inner_pair in pair.into_inner() {
                if inner_pair.as_rule() == Rule::expr {
                    expressions.push(parse_expression(inner_pair)?);
                }
            }
            break;
        }
    }

    // If there are no expressions, that's valid (empty script)
    Ok(expressions)
}

/// Parse an expression from a pest pair
fn parse_expression(pair: Pair<Rule>) -> Result<Expression, ApiError> {
    match pair.as_rule() {
        Rule::expr => {
            let inner = pair.into_inner().next().unwrap();
            parse_expression(inner)
        }
        Rule::or_expr => {
            let mut inner = pair.into_inner();
            let first = parse_expression(inner.next().unwrap());

            inner.fold(first, |acc, pair| {
                // This handles "||" operators
                Ok(Expression::Or(
                    Box::new(acc?),
                    Box::new(parse_expression(pair)?),
                ))
            })
        }
        Rule::and_expr => {
            let mut inner = pair.into_inner();
            let first = parse_expression(inner.next().unwrap());

            inner.fold(first, |acc, pair| {
                // This handles "&&" operators
                Ok(Expression::And(
                    Box::new(acc?),
                    Box::new(parse_expression(pair)?),
                ))
            })
        }
        Rule::primary_expr => {
            let inner = pair.into_inner().next().unwrap();
            match inner.as_rule() {
                Rule::function_call => Ok(parse_function(inner)?),
                Rule::expr => Ok(Expression::Group(Box::new(parse_expression(inner)?))),
                _ => unreachable!(),
            }
        }
        _ => unreachable!("Unexpected rule: {:?}", pair.as_rule()),
    }
}

/// Parse a function call from a pest pair
fn parse_function(pair: Pair<Rule>) -> Result<Expression, ApiError> {
    let mut inner = pair.into_inner();
    let function_name = inner.next().unwrap().as_str();

    // Disallow branch() as a top-level function call
    if function_name == "branch" {
        return Err(ApiError::ParseScript(
            "branch() can only be used as an argument to other functions".to_string(),
        ));
    }

    // Parse arguments
    let mut args = Vec::new();
    for p in inner {
        if [Rule::string_literal, Rule::path_literal, Rule::identifier].contains(&p.as_rule()) {
            // Direct string arguments become Key::String
            let raw_str = p.as_str();
            let arg_str =
                if p.as_rule() == Rule::string_literal || p.as_rule() == Rule::path_literal {
                    &raw_str[1..raw_str.len() - 1]
                } else {
                    raw_str
                };
            args.push(Key::String(arg_str));
        } else if p.as_rule() == Rule::function_call {
            // Handle nested function calls - only allow branch()
            let func_pairs = p.clone().into_inner();
            let nested_func_name = func_pairs.clone().next().unwrap().as_str();

            if nested_func_name == "branch" {
                // Process branch() argument
                let branch_args: Vec<&str> = func_pairs
                    .skip(1) // Skip the function name
                    .filter_map(|arg| {
                        if [Rule::string_literal, Rule::path_literal, Rule::identifier]
                            .contains(&arg.as_rule())
                        {
                            let raw_str = arg.as_str();
                            let arg_str = if arg.as_rule() == Rule::string_literal
                                || arg.as_rule() == Rule::path_literal
                            {
                                &raw_str[1..raw_str.len() - 1]
                            } else {
                                raw_str
                            };
                            Some(arg_str)
                        } else {
                            None
                        }
                    })
                    .collect();

                if branch_args.len() != 1 {
                    return Err(ApiError::ParseScript(
                        "branch() requires exactly one argument".to_string(),
                    ));
                }

                args.push(Key::Branch(branch_args[0]));
            } else {
                return Err(ApiError::ParseScript(format!(
                    "Only branch() can be used as a nested function: got {}",
                    nested_func_name
                )));
            }
        }
    }

    // Create the appropriate Function based on name and arguments
    let function = match function_name {
        "check_eq" if args.len() == 1 => Function::CheckEq(args[0].clone()),
        "check_signature" if args.len() == 2 => {
            let key = args[0].clone();
            match &args[1] {
                Key::String(msg) => Function::CheckSignature(key, msg),
                Key::Branch(_) => {
                    return Err(ApiError::ParseScript(
                        "Branch cannot be used as message argument".to_string(),
                    ));
                }
            }
        }
        "check_preimage" if args.len() == 1 => Function::CheckPreimage(args[0].clone()),
        "push" if args.len() == 1 => Function::Push(args[0].clone()),
        _ => {
            let msg = format!(
                "Unsupported function call: {} with {} args",
                function_name,
                args.len()
            );
            return Err(ApiError::ParseScript(msg));
        }
    };

    Ok(Expression::Function(function))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_expression() {
        let simple_script = r#"check_signature("/key", "/msg") || check_preimage("/hash")"#;
        let expressions = parse(simple_script).expect("Failed to parse simple script");

        // Should have one top-level OR expression
        assert_eq!(expressions.len(), 1);

        if let Expression::Or(left, right) = &expressions[0] {
            // Check left side of OR
            if let Expression::Function(Function::CheckSignature(key, msg)) = &**left {
                match key {
                    Key::String(key_str) => assert_eq!(*key_str, "/key"),
                    Key::Branch(_) => panic!("Expected string key, got Branch"),
                }
                assert_eq!(*msg, "/msg");
            } else {
                panic!("Expected CheckSignature function on left side of OR");
            }

            // Check right side of OR
            if let Expression::Function(Function::CheckPreimage(hash)) = &**right {
                match hash {
                    Key::String(hash_str) => assert_eq!(*hash_str, "/hash"),
                    Key::Branch(_) => panic!("Expected string hash, got Branch"),
                }
            } else {
                panic!("Expected CheckPreimage function on right side of OR");
            }
        } else {
            panic!("Expected OR expression at top level");
        }
    }

    #[test]
    fn test_parse_with_comments() {
        let script_str = r#"
        // then check a possible threshold sig...
        check_signature("/recoverykey", "/entry/") ||

        // then check a possible pubkey sig...
        check_signature("/pubkey", "/entry/") ||

        // then the pre-image proof...
        check_preimage("/hash")
    "#;

        let expressions = parse(script_str).expect("Failed to parse script with comments");

        // Should have at least one expression
        assert!(!expressions.is_empty());

        // Let's collect all the function calls in order of execution
        let mut functions = Vec::new();
        collect_functions(&expressions[0], &mut functions);

        // Verify we have exactly 3 function calls
        assert_eq!(
            functions.len(),
            3,
            "Expected 3 function calls, got {}",
            functions.len()
        );

        // Check each function is the expected type with expected arguments
        match &functions[0] {
            Function::CheckSignature(key, msg) => {
                match key {
                    Key::String(key_str) => assert_eq!(*key_str, "/recoverykey"),
                    Key::Branch(_) => panic!("Expected string key, got Branch"),
                }
                assert_eq!(*msg, "/entry/");
            }
            other => panic!("First function should be CheckSignature, got {:?}", other),
        }

        match &functions[1] {
            Function::CheckSignature(key, msg) => {
                match key {
                    Key::String(key_str) => assert_eq!(*key_str, "/pubkey"),
                    Key::Branch(_) => panic!("Expected string key, got Branch"),
                }
                assert_eq!(*msg, "/entry/");
            }
            other => panic!("Second function should be CheckSignature, got {:?}", other),
        }

        match &functions[2] {
            Function::CheckPreimage(hash) => match hash {
                Key::String(hash_str) => assert_eq!(*hash_str, "/hash"),
                Key::Branch(_) => panic!("Expected string hash, got Branch"),
            },
            other => panic!("Third function should be CheckPreimage, got {:?}", other),
        }
    }

    // Helper function to collect all Function nodes in execution order
    fn collect_functions<'a>(expr: &'a Expression<'a>, functions: &mut Vec<Function<'a>>) {
        match expr {
            Expression::Function(f) => functions.push(f.clone()),
            Expression::And(left, right) => {
                collect_functions(left, functions);
                collect_functions(right, functions);
            }
            Expression::Or(left, right) => {
                // For OR expressions, the left side is tried first, then the right
                collect_functions(left, functions);
                collect_functions(right, functions);
            }
            Expression::Group(inner) => {
                collect_functions(inner, functions);
            }
        }
    }

    #[test]
    fn test_parse_nested_functions() {
        let script_str = r#"check_signature(branch("pubkey"), "/entry/")"#;
        let expressions = parse(script_str).expect("Failed to parse nested functions");

        assert_eq!(expressions.len(), 1);

        if let Expression::Function(Function::CheckSignature(key, msg)) = &expressions[0] {
            match key {
                Key::Branch(branch_str) => assert_eq!(*branch_str, "pubkey"),
                Key::String(_) => panic!("Expected Branch key, got String"),
            }
            assert_eq!(*msg, "/entry/");
        } else {
            panic!("Expected CheckSignature with nested Branch function");
        }
    }

    #[test]
    fn test_parse_with_grouping() {
        let script_str = r#"(check_eq("/value1") && check_eq("/value2"))"#;
        let expressions = parse(script_str).expect("Failed to parse grouped expression");

        assert_eq!(expressions.len(), 1);

        if let Expression::Group(inner) = &expressions[0] {
            if let Expression::And(left, right) = &**inner {
                // Check both sides of AND
                if let Expression::Function(Function::CheckEq(val1)) = &**left {
                    match val1 {
                        Key::String(val_str) => assert_eq!(*val_str, "/value1"),
                        Key::Branch(_) => panic!("Expected String key, got Branch"),
                    }
                } else {
                    panic!("Expected CheckEq on left side of AND");
                }

                if let Expression::Function(Function::CheckEq(val2)) = &**right {
                    match val2 {
                        Key::String(val_str) => assert_eq!(*val_str, "/value2"),
                        Key::Branch(_) => panic!("Expected String key, got Branch"),
                    }
                } else {
                    panic!("Expected CheckEq on right side of AND");
                }
            } else {
                panic!("Expected AND expression inside group");
            }
        } else {
            panic!("Expected Group expression at top level");
        }
    }

    #[test]
    fn test_parse_all_function_types() {
        let test_script = r#"
            check_eq("/match") && 
            check_signature("/pubkey/path", "/message/path") && 
            check_preimage("/hash") && 
            push("/stack/path") 
        "#;

        let expressions = parse(test_script).expect("Failed to parse all function types");

        // Should have one expression (all connected by AND operators)
        assert_eq!(expressions.len(), 1);

        // Verify the structure has all expected function types
        // This is simplified - a complete test would traverse the full AND chain
        let mut found_check_eq = false;
        let mut found_check_signature = false;
        let mut found_check_preimage = false;
        let mut found_push = false;

        // Helper function to check for function types in an expression
        fn check_for_functions(
            expr: &Expression,
            check_eq: &mut bool,
            check_sig: &mut bool,
            check_preimage: &mut bool,
            push: &mut bool,
        ) {
            match expr {
                Expression::Function(f) => match f {
                    Function::CheckEq(_) => *check_eq = true,
                    Function::CheckSignature(_, _) => *check_sig = true,
                    Function::CheckPreimage(_) => *check_preimage = true,
                    Function::Push(_) => *push = true,
                },
                Expression::And(left, right) => {
                    check_for_functions(left, check_eq, check_sig, check_preimage, push);
                    check_for_functions(right, check_eq, check_sig, check_preimage, push);
                }
                Expression::Or(left, right) => {
                    check_for_functions(left, check_eq, check_sig, check_preimage, push);
                    check_for_functions(right, check_eq, check_sig, check_preimage, push);
                }
                Expression::Group(inner) => {
                    check_for_functions(inner, check_eq, check_sig, check_preimage, push);
                }
            }
        }

        check_for_functions(
            &expressions[0],
            &mut found_check_eq,
            &mut found_check_signature,
            &mut found_check_preimage,
            &mut found_push,
        );

        assert!(found_check_eq, "CheckEq function not found");
        assert!(found_check_signature, "CheckSignature function not found");
        assert!(found_check_preimage, "CheckPreimage function not found");
        assert!(found_push, "Push function not found");
    }

    #[test]
    fn test_parse_error_handling() {
        // Wrong number of arguments
        let invalid_script = r#"check_eq("/test", "/extra")"#;
        assert!(
            parse(invalid_script).is_err(),
            "Should error with too many arguments"
        );

        // Too few arguments
        let invalid_script = r#"check_signature("/key")"#;
        assert!(
            parse(invalid_script).is_err(),
            "Should error with too few arguments"
        );

        // Unknown function
        let invalid_script = r#"unknown_function("/test")"#;
        assert!(
            parse(invalid_script).is_err(),
            "Should error with unknown function"
        );
    }

    #[test]
    fn test_semicolon_terminated_statements() {
        let unlock = r#"
        // push the serialized Entry as the message
        push("/entry/"); 

        // push the proof data
        push("/entry/proof");
    "#;

        let expressions = parse(unlock).expect("Failed to parse script with semicolons");

        // Should have two expressions
        assert_eq!(expressions.len(), 2);

        // Check the first expression is push("/entry/")
        if let Expression::Function(Function::Push(key)) = &expressions[0] {
            match key {
                Key::String(path) => assert_eq!(*path, "/entry/"),
                Key::Branch(_) => panic!("Expected string key, got Branch"),
            }
        } else {
            panic!("Expected Push function for first expression");
        }

        // Check the second expression is push("/entry/proof")
        if let Expression::Function(Function::Push(key)) = &expressions[1] {
            match key {
                Key::String(path) => assert_eq!(*path, "/entry/proof"),
                Key::Branch(_) => panic!("Expected string key, got Branch"),
            }
        } else {
            panic!("Expected Push function for second expression");
        }
    }
}
