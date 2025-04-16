;; SPDX-License-Identifier: FSL-1.1
(module
    ;; importing the wac logging function
    (import "wacc" "_log" (func $log (param i32 i32) (result i32)))

    ;; function to log the greeting
    (func $main (export "move_every_zig") (param) (result i32)
        i32.const 0
        i32.const 12
        call $log
        return
    )

    ;; export the memory
    (memory (export "memory") 1)

    ;; put the greeting meeting in the memory
    (data (i32.const 0) "Hello World!")
)
