//===- Fuchsia/Process.cpp - Fuchsia Process Implementation --- -*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file provides the Fuchsia implementation of the Process class.
//
//===----------------------------------------------------------------------===//

#include "Fuchsia.h"

#include "llvm/ADT/Hashing.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Support/ManagedStatic.h"
#include "llvm/Support/Mutex.h"
#include "llvm/Support/MutexGuard.h"

#include <fcntl.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/random.h>
#include <termios.h>
#include <unistd.h>
#include <zircon/syscalls.h>

using namespace llvm;
using namespace sys;

unsigned Process::getPageSize() {
  return static_cast<unsigned>(::getpagesize());
}

size_t Process::GetMallocUsage() {
#warning Cannot get malloc info on this platform
  return 0;
}

void Process::GetTimeUsage(TimePoint<> &elapsed, std::chrono::nanoseconds &user_time,
                           std::chrono::nanoseconds &sys_time) {
  elapsed = std::chrono::system_clock::now();
  user_time = std::chrono::microseconds::zero();
  sys_time = std::chrono::microseconds::zero();
}

// Some LLVM programs such as bugpoint produce core files as a normal part of
// their operation. To prevent the disk from filling up, this function
// does what's necessary to prevent their generation.
void Process::PreventCoreFiles() {
#warning Cannot get usage times on this platform
  coreFilesPrevented = true;
}

Optional<std::string> Process::GetEnv(StringRef Name) {
  std::string NameStr = Name.str();
  const char *Val = ::getenv(NameStr.c_str());
  if (!Val)
    return None;
  return std::string(Val);
}

std::error_code
Process::GetArgumentVector(SmallVectorImpl<const char *> &ArgsOut,
                           ArrayRef<const char *> ArgsIn,
                           SpecificBumpPtrAllocator<char> &) {
  ArgsOut.append(ArgsIn.begin(), ArgsIn.end());

  return std::error_code();
}

std::error_code Process::FixupStandardFileDescriptors() {
  return std::error_code();
}

std::error_code Process::SafelyCloseFileDescriptor(int FD) {
  if (::close(FD) < 0)
    return std::error_code(errno, std::generic_category());
  return std::error_code();
}

bool Process::StandardInIsUserInput() {
  return FileDescriptorIsDisplayed(STDIN_FILENO);
}

bool Process::StandardOutIsDisplayed() {
  return FileDescriptorIsDisplayed(STDOUT_FILENO);
}

bool Process::StandardErrIsDisplayed() {
  return FileDescriptorIsDisplayed(STDERR_FILENO);
}

bool Process::FileDescriptorIsDisplayed(int fd) {
  return isatty(fd);
}

static unsigned getColumns(int FileID) {
  // If COLUMNS is defined in the environment, wrap to that many columns.
  if (const char *ColumnsStr = std::getenv("COLUMNS")) {
    int Columns = std::atoi(ColumnsStr);
    if (Columns > 0)
      return Columns;
  }

  // Try to determine the width of the terminal.
  struct winsize ws;
  if (ioctl(FileID, TIOCGWINSZ, &ws) == 0)
    return ws.ws_col;

  return 0;
}

unsigned Process::StandardOutColumns() {
  if (!StandardOutIsDisplayed())
    return 0;

  return getColumns(1);
}

unsigned Process::StandardErrColumns() {
  if (!StandardErrIsDisplayed())
    return 0;

  return getColumns(2);
}

bool Process::FileDescriptorHasColors(int fd) {
  return FileDescriptorIsDisplayed(fd);
}

bool Process::StandardOutHasColors() {
  return FileDescriptorHasColors(STDOUT_FILENO);
}

bool Process::StandardErrHasColors() {
  return FileDescriptorHasColors(STDERR_FILENO);
}

void Process::UseANSIEscapeCodes(bool /*enable*/) {
  // No effect.
}

bool Process::ColorNeedsFlush() {
  // No, we use ANSI escape sequences.
  return false;
}

const char *Process::OutputColor(char code, bool bold, bool bg) {
  return colorcodes[bg?1:0][bold?1:0][code&7];
}

const char *Process::OutputBold(bool bg) {
  return "\033[1m";
}

const char *Process::OutputReverse() {
  return "\033[7m";
}

const char *Process::ResetColor() {
  return "\033[0m";
}

unsigned llvm::sys::Process::GetRandomNumber() {
  unsigned r;
  size_t n = sizeof(r);
  int err = getentropy(&r, n);
  if (err) {
    std::string ErrMsg;
    MakeErrMsg(&ErrMsg, "Could not generate a random number", err);
    report_fatal_error(ErrMsg);
  }
  return r;
}
