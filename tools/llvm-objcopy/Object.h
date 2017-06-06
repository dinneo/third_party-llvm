//===- Object.h -------------------------------------------------*- C++ -*-===//
//
//                             The LLVM Linker
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_OBJCOPY_OBJECT_H
#define LLVM_OBJCOPY_OBJECT_H

#include "llvm/Object/Binary.h"
#include "llvm/Object/ELFObjectFile.h"
#include "llvm/Object/ObjectFile.h"
#include "llvm/Support/ELF.h"
#include "llvm/Support/FileOutputBuffer.h"
#include "llvm/Support/TargetSelect.h"

class StringTableSection;

class SectionBase {
public:
  llvm::StringRef Name;
  llvm::ELF::Elf64_Word NameIndex;
  llvm::ELF::Elf64_Word Type;
  llvm::ELF::Elf64_Xword Flags;
  llvm::ELF::Elf64_Xword Size;
  llvm::ELF::Elf64_Xword Link;
  llvm::ELF::Elf64_Addr Addr;
  llvm::ELF::Elf64_Off Offset;
  llvm::ELF::Elf64_Off Info;
  llvm::ELF::Elf64_Xword Align;
  llvm::ELF::Elf64_Word EntrySize;
  llvm::ELF::Elf64_Half Index;
  llvm::ELF::Elf64_Off HeaderOffset;

  virtual ~SectionBase() {}
  // TODO: make initlize be based on file and section header
  virtual void initlize(
    const llvm::object::ELFFile<llvm::object::ELF64LE> &elfFile,
    const llvm::object::ELF64LE::Shdr &) = 0;
  virtual void finalize() = 0;
  virtual void finalizeSize();
  // TODO: make this not crappy
  void writeHeader(llvm::FileOutputBuffer &) const;
  virtual void writeSection(llvm::FileOutputBuffer &) const = 0;
};

class Segment {
private:
  std::vector<const SectionBase *> Sections;

public:
  llvm::ELF::Elf64_Word Type;
  llvm::ELF::Elf64_Off Offset;
  llvm::ELF::Elf64_Addr VAddr;
  llvm::ELF::Elf64_Xword FileSize;
  llvm::ELF::Elf64_Xword MemSize;
  llvm::ELF::Elf64_Word Flags;
  llvm::ELF::Elf64_Xword Align;
  uint32_t Index;

  void addSection(const SectionBase* sec) { Sections.push_back(sec); }
  void writeHeader(llvm::FileOutputBuffer &) const;
  void finalize();
};

class Section : public SectionBase {
private:
  llvm::ArrayRef<uint8_t> Data;

public:
  virtual void initlize(
    const llvm::object::ELFFile<llvm::object::ELF64LE> &,
    const llvm::object::ELF64LE::Shdr &) override;
  void finalize() override;
  void writeSection(llvm::FileOutputBuffer &) const override;
};

class StringTableSection : public SectionBase {
private:
  std::map<llvm::StringRef, uint32_t> Strings;

public:
  void addString(llvm::StringRef);
  void removeString(llvm::StringRef);
  llvm::ELF::Elf64_Word findIndex(llvm::StringRef) const;
  virtual void initlize(
    const llvm::object::ELFFile<llvm::object::ELF64LE> &,
    const llvm::object::ELF64LE::Shdr &) override;
  void finalizeSize() override;
  void finalize() override;
  void writeSection(llvm::FileOutputBuffer &) const override;
};

class Object {
private:
  typedef std::unique_ptr<SectionBase> SecPtr;

  StringTableSection *SectionNames;
  std::vector<SecPtr> Sections;
  llvm::SmallVector<Segment, 11> Segments;

  SecPtr constructSection(llvm::ELF::Elf64_Word);
  void readProgramHeaders(const llvm::object::ELFFile<llvm::object::ELF64LE> &);
  void readSectionHeaders(const llvm::object::ELFFile<llvm::object::ELF64LE> &);
  void writeHeader(llvm::FileOutputBuffer &) const;
  void writeProgramHeaders(llvm::FileOutputBuffer &) const;
  void writeSectionData(llvm::FileOutputBuffer &) const;
  void writeSectionHeaders(llvm::FileOutputBuffer &) const;

public:

  uint8_t Ident[16];
  llvm::ELF::Elf64_Half Type;
  llvm::ELF::Elf64_Half Machine;
  llvm::ELF::Elf64_Word Version;
  llvm::ELF::Elf64_Addr Entry;
  llvm::ELF::Elf64_Off SHOffset;
  llvm::ELF::Elf64_Word Flags;

  Object(const llvm::object::ELFObjectFile<llvm::object::ELF64LE>&);
  size_t totalSize() const;
  void finalize();
  void write(llvm::FileOutputBuffer &);
};

#endif
