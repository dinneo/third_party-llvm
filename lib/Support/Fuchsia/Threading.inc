//===- Fuchsia/Threading.inc - Fuchsia Threading Implementation -*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file provides the Fuchsia specific implementation of Threading functions.
//
//===----------------------------------------------------------------------===//

#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/Twine.h"

#include <pthread.h>
#include <zircon/process.h>
#include <zircon/syscalls.h>
#include <unistd.h>

namespace {
  struct ThreadInfo {
    void(*UserFn)(void *);
    void *UserData;
  };
}

static void *ExecuteOnThread_Dispatch(void *Arg) {
  ThreadInfo *TI = reinterpret_cast<ThreadInfo*>(Arg);
  TI->UserFn(TI->UserData);
  return nullptr;
}

void llvm::llvm_execute_on_thread(void(*Fn)(void*), void *UserData,
  unsigned RequestedStackSize) {
  ThreadInfo Info = { Fn, UserData };
  pthread_attr_t Attr;
  pthread_t Thread;

  // Construct the attributes object.
  if (::pthread_attr_init(&Attr) != 0)
    return;

  // Set the requested stack size, if given.
  if (RequestedStackSize != 0) {
    if (::pthread_attr_setstacksize(&Attr, RequestedStackSize) != 0)
      goto error;
  }

  // Construct and execute the thread.
  if (::pthread_create(&Thread, &Attr, ExecuteOnThread_Dispatch, &Info) != 0)
    goto error;

  // Wait for the thread and clean up.
  ::pthread_join(Thread, nullptr);

error:
  ::pthread_attr_destroy(&Attr);
}

uint64_t llvm::get_threadid() {
  return uint64_t(pthread_self());
}

static constexpr uint32_t get_max_thread_name_length_impl() {
  return ZX_MAX_NAME_LEN;
}

uint32_t llvm::get_max_thread_name_length() {
  return get_max_thread_name_length_impl();
}

void llvm::set_thread_name(const Twine &Name) {
  // Make sure the input is null terminated.
  SmallString<64> Storage;
  StringRef NameStr = Name.toNullTerminatedStringRef(Storage);

  // Truncate from the beginning, not the end, if the specified name is too
  // long.  For one, this ensures that the resulting string is still null
  // terminated, but additionally the end of a long thread name will usually
  // be more unique than the beginning, since a common pattern is for similar
  // threads to share a common prefix.
  if (get_max_thread_name_length() > 0)
    NameStr = NameStr.take_back(get_max_thread_name_length());
  zx_handle_t handle = _zx_thread_self();
  zx_object_set_property(handle, ZX_PROP_NAME, NameStr.data(), NameStr.size());
}

void llvm::get_thread_name(SmallVectorImpl<char> &Name) {
  Name.clear();
  zx_handle_t handle = _zx_thread_self();
  constexpr uint32_t len = get_max_thread_name_length_impl();
  char Buffer[len] = {'\0'};
  if (zx_object_get_property(handle, ZX_PROP_NAME, Buffer, len) == ZX_OK)
    Name.append(Buffer, Buffer + strlen(Buffer));
}
