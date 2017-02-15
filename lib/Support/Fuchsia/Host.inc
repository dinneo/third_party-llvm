//===- Fuchsia/Host.inc - Fuchsia Host Support ------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements the Fuchsia Host support.
//
//===----------------------------------------------------------------------===//

#include "llvm/Config/config.h"
#include <cctype>
#include <string>

using namespace llvm;

static std::string updateTripleOSVersion(std::string TargetTripleString) {
  return TargetTripleString;
}

std::string sys::getDefaultTargetTriple() {
  return Triple::normalize(LLVM_DEFAULT_TARGET_TRIPLE);
}
