//===-- llvm-objcopy.cpp - LLVM objcopy utility ---------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// Copy and translate object and bitcode files.
//
//===----------------------------------------------------------------------===//

#include "ObjCopier.h"
#include "llvm/Object/Archive.h"
#include "llvm/Object/Binary.h"
#include "llvm/Object/ObjectFile.h"
#include "llvm/Object/ELFObjectFile.h"
#include "llvm/Object/ELF.h"
#include "llvm/Support/FileOutputBuffer.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/ManagedStatic.h"
#include "llvm/Support/PrettyStackTrace.h"
#include "llvm/Support/Signals.h"
#include "llvm/Support/TargetRegistry.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/ToolOutputFile.h"
#include "llvm/Support/raw_ostream.h"
#include <string>
#include <system_error>

using namespace llvm;
using namespace object;

// The name this program was invoked as.
static StringRef ToolName;

namespace {
cl::opt<std::string> InputFilename(cl::Positional, cl::desc("<input>"));

cl::opt<std::string> OutputFilename(cl::Positional, cl::desc("<output>"), cl::init("-"));

cl::list<std::string>
FilterSections("section", cl::desc("Operate on the specified sections only."));
cl::alias
FilterSectionsj("j", cl::desc("Alias for --section"),
                cl::aliasopt(FilterSections));

cl::opt<bool> StripAll("strip-all",
                        cl::desc("Remove all symbols"));

cl::opt<bool> StripDebug("strip-debug",
                         cl::desc("Remove debugging symbols only"));

// strip-dwo
// strip-unneeded
}

// Show the error message and exit.
LLVM_ATTRIBUTE_NORETURN static void fail(Twine Error) {
  outs() << ToolName << ": " << Error << ".\n";
  exit(1);
}

static void failIfError(std::error_code EC, Twine Context = "") {
  if (!EC)
    return;

  std::string ContextStr = Context.str();
  if (ContextStr == "")
    fail(EC.message());
  fail(Context + ": " + EC.message());
}

static void failIfError(Error E, Twine Context = "") {
  if (!E)
    return;

  handleAllErrors(std::move(E), [&](const llvm::ErrorInfoBase &EIB) {
    std::string ContextStr = Context.str();
    if (ContextStr == "")
      fail(EIB.message());
    fail(Context + ": " + EIB.message());
  });
}

LLVM_ATTRIBUTE_NORETURN void error(Twine Message) {
  errs() << ToolName << ": " << Message << ".\n";
  errs().flush();
  exit(1);
}

LLVM_ATTRIBUTE_NORETURN void report_error(StringRef File,
                                          std::error_code EC) {
  assert(EC);
  errs() << ToolName << ": '" << File << "': " << EC.message() << ".\n";
  exit(1);
}

LLVM_ATTRIBUTE_NORETURN void report_error(StringRef File,
                                          llvm::Error E) {
  assert(E);
  std::string Buf;
  raw_string_ostream OS(Buf);
  logAllUnhandledErrors(std::move(E), OS, "");
  OS.flush();
  errs() << ToolName << ": '" << File << "': " << Buf;
  exit(1);
}

namespace {
typedef std::function<bool(llvm::object::SectionRef const &)> FilterPredicate;

class SectionFilterIterator {
public:
  SectionFilterIterator(FilterPredicate P,
                        llvm::object::section_iterator const &I,
                        llvm::object::section_iterator const &E)
      : Predicate(std::move(P)), Iterator(I), End(E) {
    ScanPredicate();
  }
  const llvm::object::SectionRef &operator*() const { return *Iterator; }
  SectionFilterIterator &operator++() {
    ++Iterator;
    ScanPredicate();
    return *this;
  }
  bool operator!=(SectionFilterIterator const &Other) const {
    return Iterator != Other.Iterator;
  }

private:
  void ScanPredicate() {
    while (Iterator != End && !Predicate(*Iterator)) {
      ++Iterator;
    }
  }
  FilterPredicate Predicate;
  llvm::object::section_iterator Iterator;
  llvm::object::section_iterator End;
};

class SectionFilter {
public:
  SectionFilter(FilterPredicate P, llvm::object::ObjectFile const &O)
      : Predicate(std::move(P)), Object(O) {}
  SectionFilterIterator begin() {
    return SectionFilterIterator(Predicate, Object.section_begin(),
                                 Object.section_end());
  }
  SectionFilterIterator end() {
    return SectionFilterIterator(Predicate, Object.section_end(),
                                 Object.section_end());
  }

private:
  FilterPredicate Predicate;
  llvm::object::ObjectFile const &Object;
};

SectionFilter ToolSectionFilter(llvm::object::ObjectFile const &O) {
  return SectionFilter([](llvm::object::SectionRef const &S) {
                         if(FilterSections.empty())
                           return true;
                         llvm::StringRef String;
                         std::error_code error = S.getName(String);
                         if (error)
                           return false;
                         return std::find(FilterSections.begin(),
                                          FilterSections.end(),
                                          String) != FilterSections.end();
                       },
                       O);
}
}

static void CopyArchive(Archive *a) {
}

static void CopyObject(ObjectFile *Obj, StringRef OutputFilename) {
  std::unique_ptr<FileOutputBuffer> Buffer;
  ErrorOr<std::unique_ptr<FileOutputBuffer>> BufferOrErr =
      FileOutputBuffer::create(OutputFilename, /*FileSize=*/50,
                               FileOutputBuffer::F_executable);
  if (auto EC = BufferOrErr.getError())
    error(EC, "failed to open " + OutputFilename);
  else
    Buffer = std::move(*BufferOrErr);

  std::error_code EC;
  std::unique_ptr<tool_output_file> Out(new tool_output_file(
      OutputFilename.data(), EC, sys::fs::F_None));
  if (EC)
    report_fatal_error(EC.message());

  std::unique_ptr<ObjCopier> C;
  createELFCopier(Obj, Out, C);
}

int main(int argc, char **argv) {
  // Print a stack trace if we signal out.
  sys::PrintStackTraceOnErrorSignal(argv[0]);
  PrettyStackTraceProgram X(argc, argv);
  llvm_shutdown_obj Y; // Call llvm_shutdown() on exit.

  // These calls are needed so that we can read bitcode correctly.
  llvm::InitializeAllTargetInfos();
  llvm::InitializeAllTargetMCs();
  llvm::InitializeAllAsmParsers();

  cl::ParseCommandLineOptions(argc, argv, "llvm objcopy utility\n");

  ToolName = argv[0];

  if (InputFilename.empty()) {
    cl::PrintHelpMessage();
    return 2;
  }

  Expected<OwningBinary<Binary>> BinaryOrErr = createBinary(InputFilename);
  if (!BinaryOrErr)
    report_error(InputFilename, BinaryOrErr.takeError());
  Binary &Binary = *BinaryOrErr.get().getBinary();

  if (Archive *a = dyn_cast<Archive>(&Binary))
    CopyArchive(a);
  else if (ObjectFile *o = dyn_cast<ObjectFile>(&Binary))
    CopyObject(o, OutputFilename);
  else
    report_error(InputFilename, object_error::invalid_file_type);

  return EXIT_SUCCESS;
}
