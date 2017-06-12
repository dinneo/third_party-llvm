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

  uint64_t Addr = 0;
  uint64_t Align = 1;
  uint32_t EntrySize = 0;
  uint64_t Flags = 0;
  uint64_t Info = 0;
  uint64_t Link = llvm::ELF::SHN_UNDEF;
  uint64_t NameIndex = 0;
  uint64_t Offset = 0;
  uint64_t Size = 0;
  uint64_t Type = llvm::ELF::SHT_NULL;

  virtual ~SectionBase() {}
  virtual void finalize();
  template <class ELFT> void writeHeader(llvm::FileOutputBuffer &Out) const;
  virtual void writeSection(llvm::FileOutputBuffer &Out) const = 0;
};

class Segment {
private:
  struct SectionCompare {
    bool operator()(const SectionBase *Lhs, const SectionBase *Rhs) const {
      return Lhs->Addr < Rhs->Addr;
    }
  };

  std::set<const SectionBase *, SectionCompare> Sections;

public:
  uint64_t Align;
  uint64_t FileSize;
  uint32_t Flags;
  uint32_t Index;
  uint64_t MemSize;
  uint64_t Offset;
  uint64_t Type;
  uint64_t VAddr;

  void finalize();
  const SectionBase * firstSection() const {
    if(Sections.size())
      return *Sections.begin();
    return nullptr;
  }
  void addSection(const SectionBase *sec) { Sections.insert(sec); }
  template <class ELFT> void writeHeader(llvm::FileOutputBuffer &Out) const;
};

class Section : public SectionBase {
private:
  llvm::ArrayRef<uint8_t> Contents;

public:
  Section(llvm::ArrayRef<uint8_t> Data) : Contents(Data) {}
  void writeSection(llvm::FileOutputBuffer &Out) const override;
};

class StringTableSection : public SectionBase {
private:
  std::map<llvm::StringRef, uint32_t> Strings;

public:
  StringTableSection() {
    Type = llvm::ELF::SHT_STRTAB;
  }

  void addString(llvm::StringRef Name);
  void removeString(llvm::StringRef Name);
  uint32_t findIndex(llvm::StringRef Name) const;
  void finalize() override;
  void writeSection(llvm::FileOutputBuffer &Out) const override;
  static bool classof(const SectionBase *S) {
    return S->Type == llvm::ELF::SHT_STRTAB;
  }
};

struct Symbol {
  llvm::StringRef Name;
  uint32_t NameIndex;
  uint8_t Binding;
  uint8_t Type;
  SectionBase *DefinedIn;
  uint64_t Value;
  uint64_t Size;
};

// The symbol data changes from ELFT to ELFT so we need to template it. This
// lets us implement writeSection
template <class ELFT> class SymbolTableSection : public SectionBase {
private:
  StringTableSection &SymbolNames;
  std::map<llvm::StringRef, Symbol> Symbols;
  std::vector<Symbol> FinalSymbols;

public:
  SymbolTableSection(StringTableSection &SymNames) : SymbolNames(SymNames) {
    Type = llvm::ELF::SHT_SYMTAB;
    Size = sizeof(ELFT::Sym);
    Align = sizeof(ELFT::Word);
    EntrySize = sizeof(ELFT::Sym);
  }

  void addSymbol(StringRef, uint8_t, SectionBase *, uint64_t, uint64_t);
  void removeSymbol(StringRef);
  void finalize() override;
  void writeSection(llvm::FileOutputBuffer &) const override;
  static bool classof(const SectionBase *S) {
    return S->Type == llvm::ELF::SHT_SYMTAB;
  }
};

template<class ELFT>
class Object {
private:
  typedef std::unique_ptr<SectionBase> SecPtr;
  typedef typename ELFT::Shdr Elf_Shdr;
  typedef typename ELFT::Ehdr Elf_Ehdr;
  typedef typename ELFT::Phdr Elf_Phdr;

  StringTableSection *SectionNames;
  std::vector<SecPtr> Sections;
  std::vector<Segment> Segments;

  void sortSections();
  void assignOffsets();
  void readProgramHeaders(const llvm::object::ELFFile<ELFT> &ElfFile);
  void readSectionHeaders(const llvm::object::ELFFile<ELFT> &ElfFile);
  void writeHeader(llvm::FileOutputBuffer &Out) const;
  void writeProgramHeaders(llvm::FileOutputBuffer &Out) const;
  void writeSectionData(llvm::FileOutputBuffer &Out) const;
  void writeSectionHeaders(llvm::FileOutputBuffer &Out) const;

public:
  uint8_t Ident[16];
  uint64_t Entry;
  uint64_t SHOffset;
  uint32_t Type;
  uint32_t Machine;
  uint32_t Version;
  uint32_t Flags;

  Object(const llvm::object::ELFObjectFile<ELFT> &Obj);
  size_t totalSize() const;
  void finalize();
  void write(llvm::FileOutputBuffer &Out);
};
#endif
