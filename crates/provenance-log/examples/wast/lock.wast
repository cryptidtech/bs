;; SPDX-License-Identifier: FSL-1.1
(module
  ;; importing the wacc functions
  (import "wacc" "_check_signature" (func $check_signature (param i32 i32 i32 i32) (result i32)))
  (import "wacc" "_check_preimage"  (func $check_preimage  (param i32 i32) (result i32)))

  ;; standard lock function
  (func $main (export "move_every_zig") (param) (result i32)
    ;; Expected Stack (pubkey or preimage)
    ;; ┌──────────────────┐
    ;; │ <"/entry/proof"> │
    ;; ├──────────────────┤
    ;; │        ┆         │
    ;; ┆                  ┆

    ;; check_signature("/recovery", "/entry/")
    i32.const 7
    i32.const 9
    i32.const 0
    i32.const 7
    call $check_signature

    (if 
      (then 
        ;; if check_signature succeeded, return true
        i32.const 1
        return
      )
      (else
        ;; the threshold signature verify failed so try to verify a public
        ;; key signature as the proof 

        ;; check_signature("/pubkey", "/entry/")
        i32.const 16
        i32.const 7
        i32.const 0
        i32.const 7
        call $check_signature

        (if
          (then 
            ;; if check_signature succeeded, return true
            i32.const 1
            return
          )
          (else
            ;; the public key verification failed so try to verify a 
            ;; primage reveal as the proof 

            ;; check_preimage("/hash")
            i32.const 23
            i32.const 5
            call $check_preimage

            ;; return the results from check_preimage
            return
          )
        )
      )
    )

    ;; return false
    i32.const 0
    return
  )

  ;; export the memory
  (memory (export "memory") 1)

  ;; String constants for referenceing key-value pairs
  ;;
  ;;                    [NAME]            [IDX] [LEN]
  (data (i32.const  0)  "/entry/"  )   ;;    0     7
  (data (i32.const  7)  "/recovery")   ;;    7     9
  (data (i32.const 16)  "/pubkey"  )   ;;   16     7
  (data (i32.const 23)  "/hash"    )   ;;   23     5
)
