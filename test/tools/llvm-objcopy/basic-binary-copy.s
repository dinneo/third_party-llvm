# RUN: llvm-mc -filetype=obj -triple=x86_64-unknown-linux %s -o %t.o
# RUN: ld.lld %t.o -o %t
# RUN: llvm-objcopy -output-binary %t %t2
# RUN: od -t x2 -v %t2 | FileCheck %s
# RUN: wc -c < %t2 | FileCheck %s --check-prefix=SIZE

  .globl main
  .text
main:
  ret
  ret
  ret
  ret

# CHECK: 0000000 c3c3 c3c3
# SIZE:  4
