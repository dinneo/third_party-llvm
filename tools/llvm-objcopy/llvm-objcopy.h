//===-- llvm-objcopy.h ----------------------------------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TOOLS_LLVM_OBJCOPY_LLVM_OBJCOPY_H
#define LLVM_TOOLS_LLVM_OBJCOPY_LLVM_OBJCOPY_H

#include "llvm/Support/CommandLine.h"
#include "llvm/Support/ErrorOr.h"
#include "llvm/Support/Error.h"

namespace llvm {

LLVM_ATTRIBUTE_NORETURN void error(Twine Message);

template <typename T> T unwrapOrError(ErrorOr<T> EO) {
  if (auto EC = EO.getError())
    error((EC.message());
  return std::move(*EO);
}

template <typename T> T unwrapOrError(Expected<T> E) {
  if (!E)
    error(llvm::toString(E.takeError()));
  return std::move(*E);
}

} // namespace llvm

namespace options {
} // namespace options

#endif
