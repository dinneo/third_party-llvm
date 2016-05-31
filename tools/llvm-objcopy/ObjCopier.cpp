//===-- ObjDumper.cpp - Base dumper class -----------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "llvm/Support/ToolOutputFile.h"

namespace llvm {

ObjCopier::ObjCopier(std::unique_ptr<tool_output_file> Out) : Out(Out) {}

ObjCopier::~ObjCopier() {}

} // namespace llvm
