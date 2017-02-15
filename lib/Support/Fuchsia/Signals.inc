//===- Fuchsia/Signals.cpp - Fuchsia Signals Implementation -----*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file provides the Fuchsia specific implementation of the Signals class.
//
//===----------------------------------------------------------------------===//

#include "Fuchsia.h"

#include "llvm/ADT/STLExtras.h"
#include "llvm/Demangle/Demangle.h"
#include "llvm/Support/Format.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/FileUtilities.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/Mutex.h"
#include "llvm/Support/Program.h"
#include "llvm/Support/UniqueLock.h"
#include "llvm/Support/raw_ostream.h"

#include <algorithm>
#include <dlfcn.h>
#include <link.h>
#include <string>
#include <sys/stat.h>
#include <thread>
#include <zircon/errors.h>
#include <zircon/process.h>
#include <zircon/syscalls.h>
#include <zircon/syscalls/port.h>
#include <zircon/types.h>

using namespace llvm;

static ManagedStatic<sys::SmartMutex<true> > ExceptionMutex;

/// InterruptFunction - The function to call if ctrl-c is pressed.
static void (*InterruptFunction)() = nullptr;

static ManagedStatic<std::vector<std::string>> FilesToRemove;

static StringRef Argv0;

constexpr uint64_t ExceptionKey = 0x646a65u;

static void UnregisterHandlers() {
  // Disable exception handling in case we get another exception.
  zx_status_t Status = zx_task_bind_exception_port(
      ZX_HANDLE_INVALID, ZX_HANDLE_INVALID, ExceptionKey, 0);
  if (Status != ZX_OK) {
    exit(1);
  }
}

/// RemoveFilesToRemove - Process the FilesToRemove list. This function
/// should be called with the ExceptionMutex lock held.
/// NB: This must be an async signal safe function. It cannot allocate or free
/// memory, even in debug builds.
static void RemoveFilesToRemove() {
  // Avoid constructing ManagedStatic in the signal handler.
  // If FilesToRemove is not constructed, there are no files to remove.
  if (!FilesToRemove.isConstructed())
    return;

  // We avoid iterators in case of debug iterators that allocate or release
  // memory.
  std::vector<std::string>& FilesToRemoveRef = *FilesToRemove;
  for (unsigned i = 0, e = FilesToRemoveRef.size(); i != e; ++i) {
    const char *path = FilesToRemoveRef[i].c_str();

    // Get the status so we can determine if it's a file or directory. If we
    // can't stat the file, ignore it.
    struct stat buf;
    if (::stat(path, &buf) != 0)
      continue;

    // If this is not a regular file, ignore it. We want to prevent removal of
    // special files like /dev/null, even if the compiler is being run with the
    // super-user permissions.
    if (!S_ISREG(buf.st_mode))
      continue;

    // Otherwise, remove the file. We ignore any errors here as there is nothing
    // else we can do.
    ::unlink(path);
  }
}

static void ExceptionHandler(zx_handle_t *Port) {
  std::unique_ptr<zx_handle_t> ExceptionPort(Port);
  zx_port_packet_t Packet;
  zx_port_wait(*ExceptionPort, ZX_TIME_INFINITE, &Packet, sizeof(Packet));
  // Unbind as soon as possible so we don't receive exceptions from this thread.
  UnregisterHandlers();
  if (Packet.key != ExceptionKey) {
    //print_error("invalid crash key");
    exit(1);
  }
  {
    unique_lock<sys::SmartMutex<true>> Guard(*ExceptionMutex);
    RemoveFilesToRemove();
  }
  llvm::sys::RunSignalHandlers();
}

static void RegisterHandlers() {
  zx_status_t Status;
  zx_handle_t *ExceptionPort = new zx_handle_t;
  Status = zx_port_create(0, ExceptionPort);
  if (Status != ZX_OK) {
    //print_zx_error("zx_port_create failed", status);
    //return 1;
    exit(1);
  }

  std::thread T(ExceptionHandler, ExceptionPort);
  T.detach();

  Status = zx_task_bind_exception_port(
      zx_process_self(), *ExceptionPort, ExceptionKey, 0);
  if (Status != ZX_OK) {
    exit(1);
  }
}

void llvm::sys::RunInterruptHandlers() {
  sys::SmartScopedLock<true> Guard(*ExceptionMutex);
  RemoveFilesToRemove();
}

void llvm::sys::SetInterruptFunction(void (*IF)()) {
  {
    sys::SmartScopedLock<true> Guard(*ExceptionMutex);
    InterruptFunction = IF;
  }
  RegisterHandlers();
}

// RemoveFileOnSignal - The public API
bool llvm::sys::RemoveFileOnSignal(StringRef Filename,
                                   std::string* ErrMsg) {
  {
    sys::SmartScopedLock<true> Guard(*ExceptionMutex);
    FilesToRemove->push_back(Filename);
  }

  RegisterHandlers();
  return false;
}

// DontRemoveFileOnSignal - The public API
void llvm::sys::DontRemoveFileOnSignal(StringRef Filename) {
  sys::SmartScopedLock<true> Guard(*ExceptionMutex);
  std::vector<std::string>::reverse_iterator RI =
      find(reverse(*FilesToRemove), Filename);
  std::vector<std::string>::iterator I = FilesToRemove->end();
  if (RI != FilesToRemove->rend())
    I = FilesToRemove->erase(RI.base()-1);
}

/// AddSignalHandler - Add a function to be called when a signal is delivered
/// to the process.  The handler can have a cookie passed to it to identify
/// what instance of the handler it is.
void llvm::sys::AddSignalHandler(void (*FnPtr)(void *), void *Cookie) {
  CallBacksToRun->push_back(std::make_pair(FnPtr, Cookie));
  RegisterHandlers();
}

struct DlIteratePhdrData {
  void **StackTrace;
  int depth;
  bool first;
  const char **modules;
  intptr_t *offsets;
  const char *main_exec_name;
};

static int dl_iterate_phdr_cb(dl_phdr_info *info, size_t size, void *arg) {
  DlIteratePhdrData *data = (DlIteratePhdrData*)arg;
  const char *name = data->first ? data->main_exec_name : info->dlpi_name;
  data->first = false;
  for (int i = 0; i < info->dlpi_phnum; i++) {
    const auto *phdr = &info->dlpi_phdr[i];
    if (phdr->p_type != PT_LOAD)
      continue;
    intptr_t beg = info->dlpi_addr + phdr->p_vaddr;
    intptr_t end = beg + phdr->p_memsz;
    for (int j = 0; j < data->depth; j++) {
      if (data->modules[j])
        continue;
      intptr_t addr = (intptr_t)data->StackTrace[j];
      if (beg <= addr && addr < end) {
        data->modules[j] = name;
        data->offsets[j] = addr - info->dlpi_addr;
      }
    }
  }
  return 0;
}

static bool findModulesAndOffsets(void **StackTrace, int Depth,
                                  const char **Modules, intptr_t *Offsets,
                                  const char *MainExecutableName,
                                  StringSaver &StrPool) {
  DlIteratePhdrData data = {StackTrace, Depth,   true,
                            Modules,    Offsets, MainExecutableName};
  dl_iterate_phdr(dl_iterate_phdr_cb, &data);
  return true;
}

#if 0
#if ENABLE_BACKTRACES && defined(HAVE__UNWIND_BACKTRACE)
static int unwindBacktrace(void **StackTrace, int MaxEntries) {
  if (MaxEntries < 0)
    return 0;

  // Skip the first frame ('unwindBacktrace' itself).
  int Entries = -1;

  auto HandleFrame = [&](_Unwind_Context *Context) -> _Unwind_Reason_Code {
    // Apparently we need to detect reaching the end of the stack ourselves.
    void *IP = (void *)_Unwind_GetIP(Context);
    if (!IP)
      return _URC_END_OF_STACK;

    assert(Entries < MaxEntries && "recursively called after END_OF_STACK?");
    if (Entries >= 0)
      StackTrace[Entries] = IP;

    if (++Entries == MaxEntries)
      return _URC_END_OF_STACK;
    return _URC_NO_REASON;
  };

  _Unwind_Backtrace(
      [](_Unwind_Context *Context, void *Handler) {
        return (*static_cast<decltype(HandleFrame) *>(Handler))(Context);
      },
      static_cast<void *>(&HandleFrame));
  return std::max(Entries, 0);
}
#endif

// PrintStackTrace - In the case of a program crash or fault, print out a stack
// trace so that the user has an indication of why and where we died.
//
// On glibc systems we have the 'backtrace' function, which works nicely, but
// doesn't demangle symbols.
void llvm::sys::PrintStackTrace(raw_ostream &OS) {
#if ENABLE_BACKTRACES
  static void *StackTrace[256];
  int depth = 0;
#if defined(HAVE_BACKTRACE)
  // Use backtrace() to output a backtrace on Linux systems with glibc.
  if (!depth)
    depth = backtrace(StackTrace, static_cast<int>(array_lengthof(StackTrace)));
#endif
#if defined(HAVE__UNWIND_BACKTRACE)
  // Try _Unwind_Backtrace() if backtrace() failed.
  if (!depth)
    depth = unwindBacktrace(StackTrace,
                        static_cast<int>(array_lengthof(StackTrace)));
#endif
  if (!depth)
    return;

  if (printSymbolizedStackTrace(Argv0, StackTrace, depth, OS))
    return;
#if HAVE_DLFCN_H && __GNUG__ && !defined(__CYGWIN__)
  int width = 0;
  for (int i = 0; i < depth; ++i) {
    Dl_info dlinfo;
    dladdr(StackTrace[i], &dlinfo);
    const char* name = strrchr(dlinfo.dli_fname, '/');

    int nwidth;
    if (!name) nwidth = strlen(dlinfo.dli_fname);
    else       nwidth = strlen(name) - 1;

    if (nwidth > width) width = nwidth;
  }

  for (int i = 0; i < depth; ++i) {
    Dl_info dlinfo;
    dladdr(StackTrace[i], &dlinfo);

    OS << format("%-2d", i);

    const char* name = strrchr(dlinfo.dli_fname, '/');
    if (!name) OS << format(" %-*s", width, dlinfo.dli_fname);
    else       OS << format(" %-*s", width, name+1);

    OS << format(" %#0*lx", (int)(sizeof(void*) * 2) + 2,
                 (unsigned long)StackTrace[i]);

    if (dlinfo.dli_sname != nullptr) {
      OS << ' ';
      int res;
      char* d = itaniumDemangle(dlinfo.dli_sname, nullptr, nullptr, &res);
      if (!d) OS << dlinfo.dli_sname;
      else    OS << d;
      free(d);

      // FIXME: When we move to C++11, use %t length modifier. It's not in
      // C++03 and causes gcc to issue warnings. Losing the upper 32 bits of
      // the stack offset for a stack dump isn't likely to cause any problems.
      OS << format(" + %u",(unsigned)((char*)StackTrace[i]-
                                      (char*)dlinfo.dli_saddr));
    }
    OS << '\n';
  }
#elif defined(HAVE_BACKTRACE)
  backtrace_symbols_fd(StackTrace, depth, STDERR_FILENO);
#endif
#endif
}
#endif

static void PrintStackTraceSignalHandler(void *) {
  //PrintStackTrace(llvm::errs());
}

void llvm::sys::DisableSystemDialogsOnCrash() {}

void llvm::sys::PrintStackTraceOnErrorSignal(StringRef Argv0,
                                             bool DisableCrashReporting) {
  ::Argv0 = Argv0;

  AddSignalHandler(PrintStackTraceSignalHandler, nullptr);
}
