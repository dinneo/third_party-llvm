//===- Fuchsia/Memory.cpp - Fuchsia System Configuration --------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines some functions for various memory management utilities.
//
//===----------------------------------------------------------------------===//

#include "Fuchsia.h"

#include "llvm/Support/DataTypes.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/Process.h"

#include <zircon/process.h>
#include <zircon/syscalls.h>

namespace {

int getZirconProtectionFlags(unsigned Flags) {
  switch (Flags) {
  case llvm::sys::Memory::MF_READ:
    return ZX_VM_FLAG_PERM_READ;
  case llvm::sys::Memory::MF_WRITE:
    return ZX_VM_FLAG_PERM_WRITE;
  case llvm::sys::Memory::MF_READ|llvm::sys::Memory::MF_WRITE:
    return ZX_VM_FLAG_PERM_READ | ZX_VM_FLAG_PERM_WRITE;
  case llvm::sys::Memory::MF_READ|llvm::sys::Memory::MF_EXEC:
    return ZX_VM_FLAG_PERM_READ | ZX_VM_FLAG_PERM_EXECUTE;
  case llvm::sys::Memory::MF_READ | llvm::sys::Memory::MF_WRITE |
      llvm::sys::Memory::MF_EXEC:
    return ZX_VM_FLAG_PERM_READ | ZX_VM_FLAG_PERM_WRITE |
        ZX_VM_FLAG_PERM_EXECUTE;
  case llvm::sys::Memory::MF_EXEC:
    return ZX_VM_FLAG_PERM_EXECUTE;
  default:
    llvm_unreachable("Illegal memory protection flag specified!");
  }
  // Provide a default return value as required by some compilers.
  return 0;
}

} // anonymous namespace

namespace llvm {
namespace sys {

MemoryBlock
Memory::allocateMappedMemory(size_t NumBytes,
                             const MemoryBlock *const NearBlock,
                             unsigned PFlags,
                             std::error_code &EC) {
  EC = std::error_code();
  if (NumBytes == 0)
    return MemoryBlock();

  static const size_t PageSize = Process::getPageSize();
  const size_t NumPages = (NumBytes+PageSize-1)/PageSize;
  const size_t MappingSize = PageSize*NumPages;

  int Protect = getZirconProtectionFlags(PFlags);

  // Use any near hint and the page size to set a page-aligned starting address
  uintptr_t Start = NearBlock ? reinterpret_cast<uintptr_t>(NearBlock->base()) +
                                      NearBlock->size() : 0;
  if (Start && Start % PageSize)
    Start += PageSize - Start % PageSize;

  zx_handle_t VMO;
  zx_status_t status = _zx_vmo_create(MappingSize, 0, &VMO);
  if (status != ZX_OK) {
    EC = std::error_code(status, std::generic_category());
    return MemoryBlock();
  }

  uintptr_t Addr;
  status = zx_vmar_map(
      _zx_vmar_root_self(), 0, VMO, 0, MappingSize, Protect, &Addr);
  if (status != ZX_OK) {
    if (NearBlock) //Try again without a near hint
      return allocateMappedMemory(NumBytes, nullptr, PFlags, EC);

    EC = std::error_code(status, std::generic_category());
    return MemoryBlock();
  }

  MemoryBlock Result;
  Result.Address = reinterpret_cast<void *>(Addr);
  Result.Size = MappingSize;

  if (PFlags & MF_EXEC)
    Memory::InvalidateInstructionCache(Result.Address, Result.Size);

  return Result;
}

std::error_code
Memory::releaseMappedMemory(MemoryBlock &M) {
  if (M.Address == nullptr || M.Size == 0)
    return std::error_code();

  zx_status_t status = zx_vmar_unmap(
      _zx_vmar_root_self(), reinterpret_cast<uintptr_t>(M.Address), M.Size);
  if (status != ZX_OK)
    return std::error_code(status, std::generic_category());

  M.Address = nullptr;
  M.Size = 0;

  return std::error_code();
}

std::error_code
Memory::protectMappedMemory(const MemoryBlock &M, unsigned Flags) {
  if (M.Address == nullptr || M.Size == 0)
    return std::error_code();

  if (!Flags)
    return std::error_code(EINVAL, std::generic_category());

  int Protect = getZirconProtectionFlags(Flags);

  zx_status_t status = zx_vmar_protect(
      _zx_vmar_root_self(), reinterpret_cast<uintptr_t>(M.Address), M.Size,
      Protect);
  if (status != ZX_OK)
    return std::error_code(status, std::generic_category());

  if (Flags & MF_EXEC)
    Memory::InvalidateInstructionCache(M.Address, M.Size);

  return std::error_code();
}

/// InvalidateInstructionCache - Before the JIT can run a block of code
/// that has been emitted it must invalidate the instruction cache on some
/// platforms.
void Memory::InvalidateInstructionCache(const void *Addr,
                                        size_t Len) {
  zx_cache_flush(Addr, Len, ZX_CACHE_FLUSH_INSN);
}

} // namespace sys
} // namespace llvm
