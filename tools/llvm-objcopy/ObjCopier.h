//===-- ObjCopier.h ---------------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TOOLS_LLVM_OBJCOPY_OBJCOPIER_H
#define LLVM_TOOLS_LLVM_OBJCOPY_OBJCOPIER_H

#include "llvm/Object/ObjectFile.h"
#include "llvm/Support/ToolOutputFile.h"

#include <memory>
#include <system_error>

namespace llvm {

class ObjCopier {
public:
  ObjCopier(std::unique_ptr<tool_output_file> Out);

protected:
  std::unique_ptr<tool_output_file> Out;
};

std::error_code createELFCopier(const llvm::object::ObjectFile *Obj,
                                std::unique_ptr<tool_output_file> Out,
                                std::unique_ptr<ObjCopier> &Result);
                                

} // namespace llvm

#endif
