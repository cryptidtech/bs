;; SPDX-License-Identifier: FSL-1.1
(module
  ;; importing the wacc functions
  (import "wacc" "_check_signature" (func $check_signature (param i32 i32 i32 i32) (result i32)))

  ;; function to check a pubkey signature proof
  (func $main (export "move_every_zig") (param) (result i32)
    ;; check_signature("/pubkey", "/entry/")
    i32.const 7
    i32.const 7
    i32.const 0
    i32.const 7
    call $check_signature
    return
  )

  ;; export the memory
  (memory (export "memory") 1)

  ;; String constants for referenceing key-value pairs
  ;;
  ;;                    [NAME]          [IDX] [LEN]
  (data (i32.const  0)  "/entry/" )  ;;     0     7
  (data (i32.const  7)  "/pubkey" )  ;;     7     7
)
