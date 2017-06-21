# RUN: llvm-mc -filetype=obj -triple=x86_64-unknown-linux %s -o %t.o
# RUN: ld.lld %t.o -o %t
# RUN: printf %4092s | dd of=%t bs=1 seek=4100 conv=notrunc
# RUN: printf "\x00\x10" | dd of=%t bs=1 seek=208 conv=notrunc
# RUN: printf "\x00\x10" | dd of=%t bs=1 seek=216 conv=notrunc
# RUN: llvm-objcopy -output-binary %t %t2
# RUN: od -t x2 %t2 | FileCheck %s
# RUN: wc -c < %t2 | FileCheck %s --check-prefix=SIZE

  .globl main
  .text
main:
  ret
  ret
  ret
  ret

  .data
  .byte 50

# CHECK:       0000000 c3c3 c3c3 2020 2020 2020 2020 2020 2020
# CHECK-NEXT:  0000020 2020 2020 2020 2020 2020 2020 2020 2020
# CHECK-NEXT:  *
# CHECK-NEXT:  0010000 0032
# SIZE:        4097
