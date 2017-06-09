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

#include "llvm/ADT/iterator.h"
#include "llvm/ADT/iterator_range.h"
#include "llvm/Object/Binary.h"
#include "llvm/Object/ELFObjectFile.h"
#include "llvm/Object/ObjectFile.h"
#include "llvm/Support/ELF.h"
#include "llvm/Support/FileOutputBuffer.h"
#include "llvm/Support/TargetSelect.h"

#include <memory>
#include <set>

class Segment;

class SectionBase {
public:
  llvm::StringRef Name;
  Segment* ParrentSegment;
  uint64_t HeaderOffset;
  uint32_t Index;

  uint64_t NameIndex;
  uint64_t Type;
  uint64_t Flags;
  uint64_t Size;
  uint64_t Link;
  uint64_t Addr;
  uint64_t Offset;
  uint64_t Info;
  uint64_t Align;
  uint32_t EntrySize;

  virtual ~SectionBase() {}
  virtual void finalize();
  template<class ELFT>
  void writeHeader(llvm::FileOutputBuffer &) const;
  virtual void writeSection(llvm::FileOutputBuffer &) const = 0;
};

class Segment {
private:
  struct SectionCompare {
    bool operator()(const SectionBase * lhs, const SectionBase * rhs) const {
      return lhs->Addr < rhs->Addr;
    }
  };

  std::set<const SectionBase *, SectionCompare> Sections;

public:
  uint64_t Type;
  uint64_t Offset;
  uint64_t VAddr;
  uint64_t FileSize;
  uint64_t MemSize;
  uint64_t Align;
  uint32_t Flags;
  uint32_t Index;

  void finalize();
  const SectionBase * firstSection() const {
    if(Sections.size())
      return *Sections.begin();
    return nullptr;
  }
  void addSection(const SectionBase *sec) { Sections.insert(sec); }
  template<class ELFT>
  void writeHeader(llvm::FileOutputBuffer &) const;
};

class Section : public SectionBase {
private:
  llvm::ArrayRef<uint8_t> Contents;

public:
  Section(llvm::ArrayRef<uint8_t> Data) : Contents(Data) {}
  void writeSection(llvm::FileOutputBuffer &) const override;
};

class StringTableSection : public SectionBase {
private:
  std::map<llvm::StringRef, uint32_t> Strings;

public:
  StringTableSection() {
    Type = llvm::ELF::SHT_STRTAB;
    Flags = 0;
    Size = 0;
    Link = 0;
    Info = 0;
    Align = 1;
    EntrySize = 0;
  }

  void addString(llvm::StringRef);
  void removeString(llvm::StringRef);
  uint32_t findIndex(llvm::StringRef) const;
  void finalize() override;
  void writeSection(llvm::FileOutputBuffer &) const override;
  static bool classof(const SectionBase *S) {
    return S->Type == llvm::ELF::SHT_STRTAB;
  }
};

template<class ELFT>
class Object {
private:
  typedef std::unique_ptr<SectionBase> SecPtr;
  StringTableSection *SectionNames;
  std::vector<SecPtr> Sections;
  std::vector<Segment> Segments;

  void sortSections();
  void assignOffsets();
  void readProgramHeaders(const llvm::object::ELFFile<ELFT> &);
  void readSectionHeaders(const llvm::object::ELFFile<ELFT> &);
  void writeHeader(llvm::FileOutputBuffer &) const;
  void writeProgramHeaders(llvm::FileOutputBuffer &) const;
  void writeSectionData(llvm::FileOutputBuffer &) const;
  void writeSectionHeaders(llvm::FileOutputBuffer &) const;

public:
  uint8_t Ident[16];
  uint64_t Entry;
  uint64_t SHOffset;
  uint32_t Type;
  uint32_t Machine;
  uint32_t Version;
  uint32_t Flags;
  Object(const llvm::object::ELFObjectFile<ELFT> &);
  size_t totalSize() const;
  void finalize();
  void write(llvm::FileOutputBuffer &);
};
#endif
