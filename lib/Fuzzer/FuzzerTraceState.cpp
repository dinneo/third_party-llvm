//===- FuzzerTraceState.cpp - Trace-based fuzzer mutator ------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// Data tracing.
//===----------------------------------------------------------------------===//

#include "FuzzerDFSan.h"
#include "FuzzerDictionary.h"
#include "FuzzerInternal.h"
#include "FuzzerIO.h"
#include "FuzzerMutate.h"
#include "FuzzerTracePC.h"
#include <algorithm>
#include <cstring>
#include <map>
#include <set>
#include <thread>

namespace fuzzer {

// Declared as static globals for faster checks inside the hooks.
static bool RecordingMemmem = false;

int ScopedDoingMyOwnMemOrStr::DoingMyOwnMemOrStr;

struct LabelRange {
  uint16_t Beg, End;  // Range is [Beg, End), thus Beg==End is an empty range.

  LabelRange(uint16_t Beg = 0, uint16_t End = 0) : Beg(Beg), End(End) {}

  static LabelRange Join(LabelRange LR1, LabelRange LR2) {
    if (LR1.Beg == LR1.End) return LR2;
    if (LR2.Beg == LR2.End) return LR1;
    return {std::min(LR1.Beg, LR2.Beg), std::max(LR1.End, LR2.End)};
  }
  LabelRange &Join(LabelRange LR) {
    return *this = Join(*this, LR);
  }
  static LabelRange Singleton(const dfsan_label_info *LI) {
    uint16_t Idx = (uint16_t)(uintptr_t)LI->userdata;
    assert(Idx > 0);
    return {(uint16_t)(Idx - 1), Idx};
  }
};

struct TraceBasedMutation {
  uint32_t Pos;
  Word W;
};


class TraceState {
public:
  LabelRange GetLabelRange(dfsan_label L);
  void DFSanMemcmpCallback(size_t CmpSize, const uint8_t *Data1,
                           const uint8_t *Data2, dfsan_label L1,
                           dfsan_label L2);
  TraceState(MutationDispatcher &MD, const FuzzingOptions &Options,
             const Fuzzer *F)
      : MD(MD), Options(Options), F(F) {}

  void StartTraceRecording() {
    if (!Options.UseMemmem)
      return;
    RecordingMemmem = true;
    NumMutations = 0;
    InterestingWords.clear();
    MD.ClearAutoDictionary();
  }

  void StopTraceRecording() {
    if (!RecordingMemmem)
      return;
    for (size_t i = 0; i < NumMutations; i++) {
      auto &M = Mutations[i];
      MD.AddWordToAutoDictionary({M.W, M.Pos});
    }
    for (auto &W : InterestingWords)
      MD.AddWordToAutoDictionary({W});
  }

  void AddInterestingWord(const uint8_t *Data, size_t Size) {
    if (!RecordingMemmem || !F->InFuzzingThread()) return;
    if (Size <= 1) return;
    Size = std::min(Size, Word::GetMaxSize());
    Word W(Data, Size);
    InterestingWords.insert(W);
  }

  void EnsureDfsanLabels(size_t Size) {
    for (; LastDfsanLabel < Size; LastDfsanLabel++) {
      dfsan_label L = dfsan_create_label("input", (void *)(LastDfsanLabel + 1));
      // We assume that no one else has called dfsan_create_label before.
      if (L != LastDfsanLabel + 1) {
        Printf("DFSan labels are not starting from 1, exiting\n");
        exit(1);
      }
    }
  }

  void AddMutation(uint32_t Pos, uint32_t Size, const uint8_t *Data) {
    if (NumMutations >= kMaxMutations) return;
    auto &M = Mutations[NumMutations++];
    for (uint32_t i = 0; i< Size; i++) {
      printf("Added the word: %d", Data[i]);
    }
    printf("\nmutation data adding is done\n");
    M.Pos = Pos;
    M.W.Set(Data, Size);
  }

  void AddMutation(uint32_t Pos, uint32_t Size, uint64_t Data) {
    assert(Size <= sizeof(Data));
    AddMutation(Pos, Size, reinterpret_cast<uint8_t*>(&Data));
  }


 private:

  static const size_t kMaxMutations = 1 << 16;
  size_t NumMutations;
  TraceBasedMutation Mutations[kMaxMutations];
  // TODO: std::set is too inefficient, need to have a custom DS here.
  std::set<Word> InterestingWords;
  MutationDispatcher &MD;
  LabelRange LabelRanges[1 << (sizeof(dfsan_label) * 8)];
  size_t LastDfsanLabel = 0;
  const FuzzingOptions Options;
  const Fuzzer *F;
};

static TraceState *TS;

LabelRange TraceState::GetLabelRange(dfsan_label L) {
  LabelRange &LR = LabelRanges[L];
  if (LR.Beg < LR.End || L == 0)
    return LR;
  const dfsan_label_info *LI = dfsan_get_label_info(L);
  if (LI->l1 || LI->l2)
    return LR = LabelRange::Join(GetLabelRange(LI->l1), GetLabelRange(LI->l2));
  return LR = LabelRange::Singleton(LI);
}

void TraceState::DFSanMemcmpCallback(size_t CmpSize, const uint8_t *Data1,
                                     const uint8_t *Data2, dfsan_label L1,
                                     dfsan_label L2) {
  printf("FARAH: DFSanMemcmpCallBack!!\n");
  // assert(ReallyHaveDFSan());
  if (!F->InFuzzingThread()) return;
  // if (L1 == 0 && L2 == 0)
  //   return;  // Not actionable.
  // if (L1 != 0 && L2 != 0)
  //   return;  // Probably still actionable.
  printf("we are here\n");
  const uint8_t *Data = L1 ? Data2 : Data1;
  LabelRange LR = L1 ? GetLabelRange(L1) : GetLabelRange(L2);
  for (size_t Pos = LR.Beg; Pos + CmpSize <= LR.End; Pos++) {
    AddMutation(Pos, CmpSize, Data);
    if (Options.Verbosity >= 3)
      Printf("DFSanMemcmpCallback: Pos %d Size %d\n", Pos, CmpSize);
  }
}


void Fuzzer::StartTraceRecording() {
  if (!TS) return;
  TS->StartTraceRecording();
}

void Fuzzer::StopTraceRecording() {
  if (!TS) return;
  TS->StopTraceRecording();
}

void Fuzzer::InitializeTraceState() {
  if (!Options.UseMemmem) return;
  TS = new TraceState(MD, Options, this);
}

static size_t InternalStrnlen(const char *S, size_t MaxLen) {
  size_t Len = 0;
  for (; Len < MaxLen && S[Len]; Len++) {}
  return Len;
}

void Fuzzer::AssignTaintLabels(uint8_t *Data, size_t Size) {
  TS->EnsureDfsanLabels(Size);
  for (size_t i = 0; i < Size; i++) {
    printf("Oh yeeee :D we are assigning a label to byte number %zu of the input\n", i);
    dfsan_set_label(i + 1, &Data[i], 1);
  }
}



// Finds min of (strlen(S1), strlen(S2)).
// Needed bacause one of these strings may actually be non-zero terminated.
static size_t InternalStrnlen2(const char *S1, const char *S2) {
  size_t Len = 0;
  for (; S1[Len] && S2[Len]; Len++)  {}
  return Len;
}

}  // namespace fuzzer

using fuzzer::TS;

extern "C" {
#define DFSAN_CMP_CALLBACK(N)                                                  \
  void __dfsw___sanitizer_cov_trace_cmp##N(uint64_t Arg1, uint64_t Arg2,       \
                                           dfsan_label L1, dfsan_label L2) {   \
  }

DFSAN_CMP_CALLBACK(1)
DFSAN_CMP_CALLBACK(2)
DFSAN_CMP_CALLBACK(4)
DFSAN_CMP_CALLBACK(8)
#undef DFSAN_CMP_CALLBACK

void __dfsw___sanitizer_cov_trace_switch(uint64_t Val, uint64_t *Cases,
                                         dfsan_label L1, dfsan_label L2) {
}

void dfsan_weak_hook_memcmp(void *caller_pc, const void *s1, const void *s2,
                            size_t n, dfsan_label s1_label,
                            dfsan_label s2_label, dfsan_label n_label) {
}

void dfsan_weak_hook_strncmp(void *caller_pc, const char *s1, const char *s2,
                             size_t n, dfsan_label s1_label,
                             dfsan_label s2_label, dfsan_label n_label) {
}

void dfsan_weak_hook_strcmp(void *caller_pc, const char *s1, const char *s2,
                            dfsan_label s1_label, dfsan_label s2_label) {
  // if (!RecordingMemcmp) return;
  size_t Len1 = strlen(s1);
  size_t Len2 = strlen(s2);
  size_t N = std::min(Len1, Len2);
  if (N <= 1) return;  // Not interesting.
  dfsan_label L1 = dfsan_read_label(s1, Len1);
  dfsan_label L2 = dfsan_read_label(s2, Len2);
  TS->DFSanMemcmpCallback(N, reinterpret_cast<const uint8_t *>(s1),
                          reinterpret_cast<const uint8_t *>(s2), L1, L2);
}

// We may need to avoid defining weak hooks to stay compatible with older clang.
#ifndef LLVM_FUZZER_DEFINES_SANITIZER_WEAK_HOOOKS
# define LLVM_FUZZER_DEFINES_SANITIZER_WEAK_HOOOKS 1
#endif

#if LLVM_FUZZER_DEFINES_SANITIZER_WEAK_HOOOKS

ATTRIBUTE_INTERFACE ATTRIBUTE_NO_SANITIZE_MEMORY
void __sanitizer_weak_hook_memcmp(void *caller_pc, const void *s1,
                                  const void *s2, size_t n, int result) {
  if (fuzzer::ScopedDoingMyOwnMemOrStr::DoingMyOwnMemOrStr) return;
  if (result == 0) return;  // No reason to mutate.
  if (n <= 1) return;  // Not interesting.
  fuzzer::TPC.AddValueForMemcmp(caller_pc, s1, s2, n, /*StopAtZero*/false);
}

ATTRIBUTE_INTERFACE ATTRIBUTE_NO_SANITIZE_MEMORY
void __sanitizer_weak_hook_strncmp(void *caller_pc, const char *s1,
                                   const char *s2, size_t n, int result) {
  if (fuzzer::ScopedDoingMyOwnMemOrStr::DoingMyOwnMemOrStr) return;
  if (result == 0) return;  // No reason to mutate.
  size_t Len1 = fuzzer::InternalStrnlen(s1, n);
  size_t Len2 = fuzzer::InternalStrnlen(s2, n);
  n = std::min(n, Len1);
  n = std::min(n, Len2);
  if (n <= 1) return;  // Not interesting.
  fuzzer::TPC.AddValueForMemcmp(caller_pc, s1, s2, n, /*StopAtZero*/true);
}


ATTRIBUTE_INTERFACE ATTRIBUTE_NO_SANITIZE_MEMORY
void __sanitizer_weak_hook_strcmp(void *caller_pc, const char *s1,
                                   const char *s2, int result) {
  if (fuzzer::ScopedDoingMyOwnMemOrStr::DoingMyOwnMemOrStr) return;
  if (result == 0) return;  // No reason to mutate.
  size_t N = fuzzer::InternalStrnlen2(s1, s2);
  if (N <= 1) return;  // Not interesting.
  fuzzer::TPC.AddValueForMemcmp(caller_pc, s1, s2, N, /*StopAtZero*/true);
}

ATTRIBUTE_INTERFACE ATTRIBUTE_NO_SANITIZE_MEMORY
void __sanitizer_weak_hook_strncasecmp(void *called_pc, const char *s1,
                                       const char *s2, size_t n, int result) {
  if (fuzzer::ScopedDoingMyOwnMemOrStr::DoingMyOwnMemOrStr) return;
  return __sanitizer_weak_hook_strncmp(called_pc, s1, s2, n, result);
}

ATTRIBUTE_INTERFACE ATTRIBUTE_NO_SANITIZE_MEMORY
void __sanitizer_weak_hook_strcasecmp(void *called_pc, const char *s1,
                                      const char *s2, int result) {
  if (fuzzer::ScopedDoingMyOwnMemOrStr::DoingMyOwnMemOrStr) return;
  return __sanitizer_weak_hook_strcmp(called_pc, s1, s2, result);
}

ATTRIBUTE_INTERFACE ATTRIBUTE_NO_SANITIZE_MEMORY
void __sanitizer_weak_hook_strstr(void *called_pc, const char *s1,
                                  const char *s2, char *result) {
  if (fuzzer::ScopedDoingMyOwnMemOrStr::DoingMyOwnMemOrStr) return;
  TS->AddInterestingWord(reinterpret_cast<const uint8_t *>(s2), strlen(s2));
}

ATTRIBUTE_INTERFACE ATTRIBUTE_NO_SANITIZE_MEMORY
void __sanitizer_weak_hook_strcasestr(void *called_pc, const char *s1,
                                      const char *s2, char *result) {
  if (fuzzer::ScopedDoingMyOwnMemOrStr::DoingMyOwnMemOrStr) return;
  TS->AddInterestingWord(reinterpret_cast<const uint8_t *>(s2), strlen(s2));
}

ATTRIBUTE_INTERFACE ATTRIBUTE_NO_SANITIZE_MEMORY
void __sanitizer_weak_hook_memmem(void *called_pc, const void *s1, size_t len1,
                                  const void *s2, size_t len2, void *result) {
  if (fuzzer::ScopedDoingMyOwnMemOrStr::DoingMyOwnMemOrStr) return;
  TS->AddInterestingWord(reinterpret_cast<const uint8_t *>(s2), len2);
}

#endif  // LLVM_FUZZER_DEFINES_SANITIZER_WEAK_HOOOKS
}  // extern "C"
