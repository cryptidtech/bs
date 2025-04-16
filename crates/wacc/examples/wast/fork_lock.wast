;; SPDX-License-Identifier: FSL-1.1
(module
  ;; importing the wacc functions
  (import "wacc" "_check_signature" (func $check_signature (param i32 i32 i32 i32) (result i32)))
  (import "wacc" "_check_eq" (func $check_eq  (param i32 i32) (result i32)))
  (import "wacc" "_branch" (func $branch (param i32 i32) (result i32 i32)))

  ;; standard lock function
  (func $main (export "move_every_zig") (param) (result i32)
    ;; branch("pubkey")
    i32.const 7
    i32.const 6
    call $branch
    i32.const 0
    i32.const 7
    ;; check_signature(branch("pubkey"), "/entry/")
    call $check_signature

    (if 
      (then ;; if check_signature succeeded, return true
        i32.const 1
        return
      )
      (else ;; the signature verify failed so try to verify the first entry in the child log
        ;; branch("vlad")
        i32.const 13
        i32.const 4
        call $branch
        ;; check_eq(branch("vlad"))
        call $check_eq
        (if
          (then 
            ;; branch("pubkey")
            i32.const 7
            i32.const 6
            call $branch
            i32.const 0
            i32.const 7
            ;; check_signature(branch("pubkey"), "/entry/")
            call $check_signature
            return
          )
        )
      )
    )

    ;; check_version failed so return false
    i32.const 0
    return
  )

  ;; export the memory
  (memory (export "memory") 1)

  ;; String constants for referenceing key-value pairs
  ;;
  ;;                    [NAME]          [IDX] [LEN]
  (data (i32.const  0)  "/entry/" )  ;;     0     7
  (data (i32.const  7)  "pubkey"  )  ;;     7     6
  (data (i32.const 13)  "vlad"    )  ;;    13     4
)
