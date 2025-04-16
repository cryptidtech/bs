;; SPDX-License-Identifier: FSL-1.1
(module
  ;; importing the wacc functions
  (import "wacc" "_branch" (func $branch (param i32 i32) (result i32 i32)))
  (import "wacc" "_log" (func $log (param i32 i32) (result i32)))

  (func $main (export "move_every_zig") (param) (result i32)
    ;; branch("pubkey")
    i32.const 0
    i32.const 6
    call $branch
    ;; log(branch("pubkey"))
    call $log
    return
  )

  ;; export the memory
  (memory (export "memory") 1)

  ;; String constants for referenceing key-value pairs
  ;;
  ;;                    [NAME]                  [IDX] [LEN]
  (data (i32.const  0)  "pubkey"          )  ;;     0     6
)
