;; SPDX-License-Identifier: FSL-1.1
(module
  ;; importing the wacc functions
  (import "wacc" "_check_preimage"  (func $check_preimage  (param i32 i32) (result i32)))

  ;; function to check a preimage proof
  (func $main (export "move_every_zig") (param) (result i32)
    ;; check_preimage("/hash")
    i32.const 0
    i32.const 5
    call $check_preimage
    return
  )

  ;; export the memory
  (memory (export "memory") 1)

  ;; String constants for referenceing key-value pairs
  ;;
  ;;                    [NAME]          [IDX] [LEN]
  (data (i32.const 0)  "/hash"    )  ;;     0     5
)
