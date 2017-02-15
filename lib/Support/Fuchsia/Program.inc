//===- Fuchsia/Program.cpp - Fuchsia Program Implementation -----*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements the Fuchsia specific portion of the Program class.
//
//===----------------------------------------------------------------------===//

#include "Fuchsia.h"

#include "llvm/ADT/ScopeExit.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/Config/config.h"
#include "llvm/Support/Compiler.h"
#include "llvm/Support/Errc.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/raw_ostream.h"

#include <fdio/util.h>
#include <launchpad/launchpad.h>
#include <sys/stat.h>
#include <unistd.h>
#include <zircon/errors.h>
#include <zircon/process.h>
#include <zircon/syscalls.h>
#include <zircon/types.h>

extern char **environ;

namespace llvm {

using namespace sys;

ProcessInfo::ProcessInfo() : Pid(0), ReturnCode(0) {}

ErrorOr<std::string> sys::findProgramByName(StringRef Name,
                                            ArrayRef<StringRef> Paths) {
  assert(!Name.empty() && "Must have a name!");
  // Use the given path verbatim if it contains any slashes; this matches
  // the behavior of sh(1) and friends.
  if (Name.find('/') != StringRef::npos)
    return std::string(Name);

  SmallVector<StringRef, 16> EnvironmentPaths;
  if (Paths.empty())
    if (const char *PathEnv = std::getenv("PATH")) {
      SplitString(PathEnv, EnvironmentPaths, ":");
      Paths = EnvironmentPaths;
    }

  for (auto Path : Paths) {
    if (Path.empty())
      continue;

    // Check to see if this first directory contains the executable...
    SmallString<128> FilePath(Path);
    sys::path::append(FilePath, Name);
    if (sys::fs::can_execute(FilePath.c_str()))
      return std::string(FilePath.str()); // Found the executable!
  }
  return errc::no_such_file_or_directory;
}

static bool RedirectIO(launchpad_t *Lp, Optional<StringRef> Path, int FD,
                       std::string *ErrMsg) {
  if (!Path) // Noop
    return false;
  if (Path->empty())
    return true;

  std::string File = *Path;

  // Open the file
  int InFD = open(File.c_str(), FD == 0 ? O_RDONLY : O_WRONLY|O_CREAT, 0666);
  if (InFD == -1) {
    MakeErrMsg(ErrMsg, "Cannot open file '" + File + "' for "
              + (FD == 0 ? "input" : "output"));
    return true;
  }

  // Install it as the requested FD
  if (launchpad_clone_fd(Lp, InFD, FD) != ZX_OK) {
    MakeErrMsg(ErrMsg, "Cannot launchpad_clone_fd");
    close(InFD);
    return true;
  }
  close(InFD); // Close the original FD
  return false;
}

}

static bool Execute(ProcessInfo &PI, StringRef Program, const char **Args,
                    const char **Envp, ArrayRef<Optional<StringRef>> Redirects,
                    unsigned MemoryLimit, std::string *ErrMsg) {
  if (!llvm::sys::fs::exists(Program)) {
    if (ErrMsg)
      *ErrMsg = std::string("Executable \"") + Program.str() +
                std::string("\" doesn't exist!");
    return false;
  }

  launchpad_t* Lp = nullptr;
  launchpad_create(ZX_HANDLE_INVALID, Program.str().c_str(), &Lp);
  auto DestroyOnExit = make_scope_exit([&]() { launchpad_destroy(Lp); });
  launchpad_load_from_file(Lp, Program.str().c_str());
  size_t Argc;
  for (Argc = 0; Args[Argc]; Argc++)
    ;
  launchpad_set_args(Lp, Argc, Args);
  if (!Envp)
    Envp = const_cast<const char **>(environ);
  launchpad_set_environ(Lp, Envp);
  launchpad_clone(Lp, LP_CLONE_ALL & (~LP_CLONE_FDIO_STDIO));

  if (!Redirects.empty()) {
    // Redirect stdin
    if (RedirectIO(Lp, Redirects[0], STDIN_FILENO, ErrMsg)) { return false; }
    // Redirect stdout
    if (RedirectIO(Lp, Redirects[1], STDOUT_FILENO, ErrMsg)) { return false; }
    // Redirect stderr
    if (RedirectIO(Lp, Redirects[2], STDOUT_FILENO, ErrMsg)) { return false; }
  }

  zx_handle_t ProcessHandle = ZX_HANDLE_INVALID;
  const char *ErrorMsg = nullptr;
  zx_status_t Status = launchpad_go(Lp, &ProcessHandle, &ErrorMsg);
  if (Status != ZX_OK) {
    MakeErrMsg(ErrMsg, ErrorMsg, Status);
    return false;
  }
  
  PI.Pid = ProcessHandle;

  return true;
}

namespace llvm {

ProcessInfo sys::Wait(const ProcessInfo &PI, unsigned SecondsToWait,
                      bool WaitUntilTerminates, std::string *ErrMsg) {
  assert(PI.Pid && "invalid pid to wait on, process not started?");
  //assert(PI.ProcessHandle &&
  //       "invalid process handle to wait on, process not started?");

  auto CloseOnExit = make_scope_exit([&]() { zx_handle_close(PI.Pid); });

  zx_time_t Timeout;
  if (WaitUntilTerminates)
    Timeout = ZX_TIME_INFINITE;
  else
    Timeout = SecondsToWait * 1000 * 1000 * 1000;

  ProcessInfo WaitResult = PI;
  zx_status_t Status;

  Status = zx_object_wait_one(PI.Pid, ZX_PROCESS_TERMINATED, Timeout, nullptr);
  if (Status != ZX_OK) {
    if (Status == ZX_ERR_TIMED_OUT) {
      if (zx_task_kill(PI.Pid) != ZX_OK) {
        if (ErrMsg)
          MakeErrMsg(ErrMsg, "Failed to terminate timed-out program");
        WaitResult.ReturnCode = -2;
        return WaitResult;
      }
    } else  {
      MakeErrMsg(ErrMsg, "Error waiting for child process", Status);
      WaitResult.ReturnCode = -1;
      return WaitResult;
    }
  }

  zx_info_process_t Info;
  Status = zx_object_get_info(PI.Pid, ZX_INFO_PROCESS, &Info, sizeof(Info),
                              nullptr, nullptr);
  if (Status < 0) {
    if (ErrMsg)
      MakeErrMsg(ErrMsg, "Failed getting status for program");

    WaitResult.ReturnCode = -2;
    return WaitResult;
  }

  WaitResult.ReturnCode = Info.return_code;
  return WaitResult;
}

std::error_code sys::ChangeStdinToBinary(){
  // Do nothing, as Fuchsia doesn't differentiate between text and binary.
  return std::error_code();
}

std::error_code sys::ChangeStdoutToBinary(){
  // Do nothing, as Fuchsia doesn't differentiate between text and binary.
  return std::error_code();
}

std::error_code
llvm::sys::writeFileWithEncoding(StringRef FileName, StringRef Contents,
                                 WindowsEncodingMethod Encoding /*unused*/) {
  std::error_code EC;
  llvm::raw_fd_ostream OS(FileName, EC, llvm::sys::fs::OpenFlags::F_Text);

  if (EC)
    return EC;

  OS << Contents;

  if (OS.has_error())
    return make_error_code(errc::io_error);

  return EC;
}

bool llvm::sys::commandLineFitsWithinSystemLimits(StringRef Program, ArrayRef<const char*> Args) {
  static long ArgMax = sysconf(_SC_ARG_MAX);

  // System says no practical limit.
  if (ArgMax == -1)
    return true;

  // Conservatively account for space required by environment variables.
  long HalfArgMax = ArgMax / 2;

  size_t ArgLength = Program.size() + 1;
  for (ArrayRef<const char*>::iterator I = Args.begin(), E = Args.end();
       I != E; ++I) {
    ArgLength += strlen(*I) + 1;
    if (ArgLength > size_t(HalfArgMax)) {
      return false;
    }
  }
  return true;
}
}
