;; SPDX-License-Identifier: FSL-1.1
(module
  ;; importing the wacc push functions
  (import "wacc" "_push" (func $push (param i32 i32) (result i32)))

  ;; unlock script function
  (func $main (export "for_great_justice") (param) (result i32)
    ;; "/entry/proof", this data is either a digital signature over <"/entry/">
    i32.const 0
    i32.const 12
    call $push

    ;; Created Stack
    ;; ┌──────────────────┐
    ;; │ <"/entry/proof"> │
    ;; ├──────────────────┤
    ;; │        ┆         │
    ;; ┆                  ┆

    return
  )

  ;; export the memory
  (memory (export "memory") 1)

  ;; String constants for referenceing key-value pairs
  ;;
  ;;                   [NAME]                  [IDX] [LEN]
  (data (i32.const  0) "/entry/proof"  )  ;;     0     12
)
