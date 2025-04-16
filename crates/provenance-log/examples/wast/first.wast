;; SPDX-License-Identifier: FSL-1.1
(module
  ;; importing the wacc functions
  (import "wacc" "_check_signature" (func $check_signature (param i32 i32 i32 i32) (result i32)))

  ;; function to execute the signature check for the first entry in a plog
  (func $main (export "move_every_zig") (param) (result i32)
    ;; This is the assumed lock script used for verifying the first entry in
    ;; the provenance log. It verifies a digital signature created over
    ;; <"/entry/"> using an ephemeral public key pair that is destroyed
    ;; immediately after creation. Only the public key is recorded in the first
    ;; entry.

    ;; Expected Stack
    ;; ┌──────────────────┐
    ;; │ <"/entry/proof"> │
    ;; ├──────────────────┤
    ;; │        ┆         │
    ;; ┆                  ┆

    ;; check_signature("/ephemeral", "/entry/")
    i32.const 7
    i32.const 10
    i32.const 0
    i32.const 7
    call $check_signature
    return
  )

  ;; export the memory
  (memory (export "memory") 1)

  ;; String constants for referenceing key-value pairs
  ;;
  ;;                    [NAME]              [IDX] [LEN]
  (data (i32.const  0)  "/entry/"    )  ;;     0     7
  (data (i32.const  7)  "/ephemeral" )  ;;     7    10
)
