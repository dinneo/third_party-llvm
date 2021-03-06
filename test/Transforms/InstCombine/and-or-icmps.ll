; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; RUN: opt < %s -instcombine -S | FileCheck %s

define i1 @PR1817_1(i32 %X) {
; CHECK-LABEL: @PR1817_1(
; CHECK-NEXT:    [[B:%.*]] = icmp ult i32 %X, 10
; CHECK-NEXT:    ret i1 [[B]]
;
  %A = icmp slt i32 %X, 10
  %B = icmp ult i32 %X, 10
  %C = and i1 %A, %B
  ret i1 %C
}

define i1 @PR1817_2(i32 %X) {
; CHECK-LABEL: @PR1817_2(
; CHECK-NEXT:    [[A:%.*]] = icmp slt i32 %X, 10
; CHECK-NEXT:    ret i1 [[A]]
;
  %A = icmp slt i32 %X, 10
  %B = icmp ult i32 %X, 10
  %C = or i1 %A, %B
  ret i1 %C
}

define i1 @PR2330(i32 %a, i32 %b) {
; CHECK-LABEL: @PR2330(
; CHECK-NEXT:    [[TMP1:%.*]] = or i32 %b, %a
; CHECK-NEXT:    [[TMP2:%.*]] = icmp ult i32 [[TMP1]], 8
; CHECK-NEXT:    ret i1 [[TMP2]]
;
  %cmp1 = icmp ult i32 %a, 8
  %cmp2 = icmp ult i32 %b, 8
  %and = and i1 %cmp2, %cmp1
  ret i1 %and
}

; if LHSC and RHSC differ only by one bit:
; (X == C1 || X == C2) -> (X | (C1 ^ C2)) == C2
; PR14708: https://bugs.llvm.org/show_bug.cgi?id=14708

define i1 @or_eq_with_one_bit_diff_constants1(i32 %x) {
; CHECK-LABEL: @or_eq_with_one_bit_diff_constants1(
; CHECK-NEXT:    [[TMP1:%.*]] = or i32 %x, 1
; CHECK-NEXT:    [[TMP2:%.*]] = icmp eq i32 [[TMP1]], 51
; CHECK-NEXT:    ret i1 [[TMP2]]
;
  %cmp1 = icmp eq i32 %x, 50
  %cmp2 = icmp eq i32 %x, 51
  %or = or i1 %cmp1, %cmp2
  ret i1 %or
}

; (X != C1 && X != C2) -> (X | (C1 ^ C2)) != C2

define i1 @and_ne_with_one_bit_diff_constants1(i32 %x) {
; CHECK-LABEL: @and_ne_with_one_bit_diff_constants1(
; CHECK-NEXT:    [[TMP1:%.*]] = or i32 %x, 1
; CHECK-NEXT:    [[TMP2:%.*]] = icmp ne i32 [[TMP1]], 51
; CHECK-NEXT:    ret i1 [[TMP2]]
;
  %cmp1 = icmp ne i32 %x, 51
  %cmp2 = icmp ne i32 %x, 50
  %and = and i1 %cmp1, %cmp2
  ret i1 %and
}

; The constants are not necessarily off-by-one, just off-by-one-bit.

define i1 @or_eq_with_one_bit_diff_constants2(i32 %x) {
; CHECK-LABEL: @or_eq_with_one_bit_diff_constants2(
; CHECK-NEXT:    [[TMP1:%.*]] = or i32 %x, 32
; CHECK-NEXT:    [[TMP2:%.*]] = icmp eq i32 [[TMP1]], 97
; CHECK-NEXT:    ret i1 [[TMP2]]
;
  %cmp1 = icmp eq i32 %x, 97
  %cmp2 = icmp eq i32 %x, 65
  %or = or i1 %cmp1, %cmp2
  ret i1 %or
}

define i1 @and_ne_with_one_bit_diff_constants2(i19 %x) {
; CHECK-LABEL: @and_ne_with_one_bit_diff_constants2(
; CHECK-NEXT:    [[TMP1:%.*]] = or i19 %x, 128
; CHECK-NEXT:    [[TMP2:%.*]] = icmp ne i19 [[TMP1]], 193
; CHECK-NEXT:    ret i1 [[TMP2]]
;
  %cmp1 = icmp ne i19 %x, 65
  %cmp2 = icmp ne i19 %x, 193
  %and = and i1 %cmp1, %cmp2
  ret i1 %and
}

; Make sure the constants are treated as unsigned when comparing them.

define i1 @or_eq_with_one_bit_diff_constants3(i8 %x) {
; CHECK-LABEL: @or_eq_with_one_bit_diff_constants3(
; CHECK-NEXT:    [[TMP1:%.*]] = or i8 %x, -128
; CHECK-NEXT:    [[TMP2:%.*]] = icmp eq i8 [[TMP1]], -2
; CHECK-NEXT:    ret i1 [[TMP2]]
;
  %cmp1 = icmp eq i8 %x, 254
  %cmp2 = icmp eq i8 %x, 126
  %or = or i1 %cmp1, %cmp2
  ret i1 %or
}

define i1 @and_ne_with_one_bit_diff_constants3(i8 %x) {
; CHECK-LABEL: @and_ne_with_one_bit_diff_constants3(
; CHECK-NEXT:    [[TMP1:%.*]] = or i8 %x, -128
; CHECK-NEXT:    [[TMP2:%.*]] = icmp ne i8 [[TMP1]], -63
; CHECK-NEXT:    ret i1 [[TMP2]]
;
  %cmp1 = icmp ne i8 %x, 65
  %cmp2 = icmp ne i8 %x, 193
  %and = and i1 %cmp1, %cmp2
  ret i1 %and
}

; Use an 'add' to eliminate an icmp if the constants are off-by-one (not off-by-one-bit).
; (X == 13 | X == 14) -> X-13 <u 2

define i1 @or_eq_with_diff_one(i8 %x) {
; CHECK-LABEL: @or_eq_with_diff_one(
; CHECK-NEXT:    [[TMP1:%.*]] = add i8 %x, -13
; CHECK-NEXT:    [[TMP2:%.*]] = icmp ult i8 [[TMP1]], 2
; CHECK-NEXT:    ret i1 [[TMP2]]
;
  %cmp1 = icmp eq i8 %x, 13
  %cmp2 = icmp eq i8 %x, 14
  %or = or i1 %cmp1, %cmp2
  ret i1 %or
}

; (X != 40 | X != 39) -> X-39 >u 1

define i1 @and_ne_with_diff_one(i32 %x) {
; CHECK-LABEL: @and_ne_with_diff_one(
; CHECK-NEXT:    [[TMP1:%.*]] = add i32 %x, -39
; CHECK-NEXT:    [[TMP2:%.*]] = icmp ugt i32 [[TMP1]], 1
; CHECK-NEXT:    ret i1 [[TMP2]]
;
  %cmp1 = icmp ne i32 %x, 40
  %cmp2 = icmp ne i32 %x, 39
  %and = and i1 %cmp1, %cmp2
  ret i1 %and
}

; Make sure the constants are treated as signed when comparing them.
; PR32524: https://bugs.llvm.org/show_bug.cgi?id=32524

define i1 @or_eq_with_diff_one_signed(i32 %x) {
; CHECK-LABEL: @or_eq_with_diff_one_signed(
; CHECK-NEXT:    [[TMP1:%.*]] = add i32 %x, 1
; CHECK-NEXT:    [[TMP2:%.*]] = icmp ult i32 [[TMP1]], 2
; CHECK-NEXT:    ret i1 [[TMP2]]
;
  %cmp1 = icmp eq i32 %x, 0
  %cmp2 = icmp eq i32 %x, -1
  %or = or i1 %cmp1, %cmp2
  ret i1 %or
}

define i1 @and_ne_with_diff_one_signed(i64 %x) {
; CHECK-LABEL: @and_ne_with_diff_one_signed(
; CHECK-NEXT:    [[TMP1:%.*]] = add i64 %x, 1
; CHECK-NEXT:    [[TMP2:%.*]] = icmp ugt i64 [[TMP1]], 1
; CHECK-NEXT:    ret i1 [[TMP2]]
;
  %cmp1 = icmp ne i64 %x, -1
  %cmp2 = icmp ne i64 %x, 0
  %and = and i1 %cmp1, %cmp2
  ret i1 %and
}

; Vectors with splat constants get the same folds.

define <2 x i1> @or_eq_with_one_bit_diff_constants2_splatvec(<2 x i32> %x) {
; CHECK-LABEL: @or_eq_with_one_bit_diff_constants2_splatvec(
; CHECK-NEXT:    [[TMP1:%.*]] = or <2 x i32> %x, <i32 32, i32 32>
; CHECK-NEXT:    [[TMP2:%.*]] = icmp eq <2 x i32> [[TMP1]], <i32 97, i32 97>
; CHECK-NEXT:    ret <2 x i1> [[TMP2]]
;
  %cmp1 = icmp eq <2 x i32> %x, <i32 97, i32 97>
  %cmp2 = icmp eq <2 x i32> %x, <i32 65, i32 65>
  %or = or <2 x i1> %cmp1, %cmp2
  ret <2 x i1> %or
}

define <2 x i1> @and_ne_with_diff_one_splatvec(<2 x i32> %x) {
; CHECK-LABEL: @and_ne_with_diff_one_splatvec(
; CHECK-NEXT:    [[TMP1:%.*]] = add <2 x i32> %x, <i32 -39, i32 -39>
; CHECK-NEXT:    [[TMP2:%.*]] = icmp ugt <2 x i32> [[TMP1]], <i32 1, i32 1>
; CHECK-NEXT:    ret <2 x i1> [[TMP2]]
;
  %cmp1 = icmp ne <2 x i32> %x, <i32 40, i32 40>
  %cmp2 = icmp ne <2 x i32> %x, <i32 39, i32 39>
  %and = and <2 x i1> %cmp1, %cmp2
  ret <2 x i1> %and
}

; This is a fuzzer-generated test that would assert because
; we'd get into foldAndOfICmps() without running InstSimplify
; on an 'and' that should have been killed. It's not obvious
; why, but removing anything hides the bug, hence the long test.

define void @simplify_before_foldAndOfICmps() {
; CHECK-LABEL: @simplify_before_foldAndOfICmps(
; CHECK-NEXT:    [[A8:%.*]] = alloca i16, align 2
; CHECK-NEXT:    [[L7:%.*]] = load i16, i16* [[A8]], align 2
; CHECK-NEXT:    [[C10:%.*]] = icmp ult i16 [[L7]], 2
; CHECK-NEXT:    [[C7:%.*]] = icmp slt i16 [[L7]], 0
; CHECK-NEXT:    [[C18:%.*]] = or i1 [[C7]], [[C10]]
; CHECK-NEXT:    [[L7_LOBIT:%.*]] = ashr i16 [[L7]], 15
; CHECK-NEXT:    [[TMP1:%.*]] = sext i16 [[L7_LOBIT]] to i64
; CHECK-NEXT:    [[G26:%.*]] = getelementptr i1, i1* null, i64 [[TMP1]]
; CHECK-NEXT:    store i16 [[L7]], i16* undef, align 2
; CHECK-NEXT:    store i1 [[C18]], i1* undef, align 1
; CHECK-NEXT:    store i1* [[G26]], i1** undef, align 8
; CHECK-NEXT:    ret void
;
  %A8 = alloca i16
  %L7 = load i16, i16* %A8
  %G21 = getelementptr i16, i16* %A8, i8 -1
  %B11 = udiv i16 %L7, -1
  %G4 = getelementptr i16, i16* %A8, i16 %B11
  %L2 = load i16, i16* %G4
  %L = load i16, i16* %G4
  %B23 = mul i16 %B11, %B11
  %L4 = load i16, i16* %A8
  %B21 = sdiv i16 %L7, %L4
  %B7 = sub i16 0, %B21
  %B18 = mul i16 %B23, %B7
  %C10 = icmp ugt i16 %L, %B11
  %B20 = and i16 %L7, %L2
  %B1 = mul i1 %C10, true
  %C5 = icmp sle i16 %B21, %L
  %C11 = icmp ule i16 %B21, %L
  %C7 = icmp slt i16 %B20, 0
  %B29 = srem i16 %L4, %B18
  %B15 = add i1 %C7, %C10
  %B19 = add i1 %C11, %B15
  %C6 = icmp sge i1 %C11, %B19
  %B33 = or i16 %B29, %L4
  %C13 = icmp uge i1 %C5, %B1
  %C3 = icmp ult i1 %C13, %C6
  store i16 undef, i16* %G21
  %C18 = icmp ule i1 %C10, %C7
  %G26 = getelementptr i1, i1* null, i1 %C3
  store i16 %B33, i16* undef
  store i1 %C18, i1* undef
  store i1* %G26, i1** undef
  ret void
}

