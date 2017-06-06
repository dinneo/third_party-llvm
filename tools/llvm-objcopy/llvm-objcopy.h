//===- llvm-objcopy.h -------------------------------------------*- C++ -*-===//
//
//                             The LLVM Linker
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_OBJCOPY_H
#define LLVM_OBJCOPY_H

namespace llvm {

extern LLVM_ATTRIBUTE_NORETURN void error(Twine Message);

// This is taken from llvm-readobj
// [see here](llvm/tools/llvm-readobj/llvm-readobj.h:38)
template <class T> T unwrapOrError(Expected<T> EO) {
  if (EO)
    return *EO;
  std::string Buf;
  raw_string_ostream OS(Buf);
  logAllUnhandledErrors(EO.takeError(), OS, "");
  OS.flush();
  error(Buf);
}

}

#endif
