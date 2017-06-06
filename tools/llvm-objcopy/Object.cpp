//===- Object.cpp -----------------------------------------------*- C++ -*-===//
//
//                             The LLVM Linker
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "Object.h"
#include "llvm-objcopy.h"

using namespace llvm;
using namespace object;
using namespace ELF;

void Segment::writeHeader(FileOutputBuffer &Out) const {
  uint8_t *Buf = Out.getBufferStart();
  Buf += sizeof(Elf64_Ehdr) + Index * sizeof(ELF64LE::Phdr);
  ELF64LE::Phdr &Phdr = *reinterpret_cast<ELF64LE::Phdr *>(Buf);
  Phdr.p_type = Type;
  Phdr.p_flags = Flags;
  Phdr.p_offset = Offset;
  Phdr.p_vaddr = VAddr;
  Phdr.p_paddr = VAddr; // TODO: add PAddr to Segment
  Phdr.p_filesz = FileSize;
  Phdr.p_memsz = MemSize;
  Phdr.p_align = Align;
}

void Segment::finalize() {
  auto CompOffset = [](const SectionBase *a, const SectionBase *b) -> bool {
    return a->Offset < b->Offset;
  };
  auto MinElem =
      std::min_element(std::begin(Sections), std::end(Sections), CompOffset);
  Offset = (**MinElem).Offset;
  FileSize = 0;
  for (auto Section : Sections)
    if (Section->Type != SHT_NOBITS)
      FileSize += Section->Size;
}

void SectionBase::finalizeSize() { }

void SectionBase::writeHeader(FileOutputBuffer &Out) const {
  uint8_t *Buf = Out.getBufferStart();
  Buf += HeaderOffset;
  ELF64LE::Shdr &Shdr = *reinterpret_cast<ELF64LE::Shdr *>(Buf);
  Shdr.sh_name = NameIndex;
  Shdr.sh_type = Type;
  Shdr.sh_flags = Flags;
  Shdr.sh_addr = Addr;
  Shdr.sh_offset = Offset;
  Shdr.sh_size = Size;
  Shdr.sh_link = Link;
  Shdr.sh_info = Info;
  Shdr.sh_addralign = Align;
  Shdr.sh_entsize = EntrySize;
}

void Section::initlize(
  const llvm::object::ELFFile<llvm::object::ELF64LE> &ElfFile,
  const llvm::object::ELF64LE::Shdr &Shdr) {
  Data = unwrapOrError(ElfFile.getSectionContents(&Shdr));
}

void Section::finalize() {}

void Section::writeSection(FileOutputBuffer &Out) const {
  uint8_t *Buf = Out.getBufferStart() + Offset;
  std::copy(std::begin(Data), std::end(Data), Buf);
}

void StringTableSection::addString(StringRef Name) { Strings[Name] = 0; }
void StringTableSection::removeString(StringRef Name) { Strings.erase(Name); }
Elf64_Word StringTableSection::findIndex(StringRef Name) const {
  auto Iter = Strings.find(Name);
  if(Iter == std::end(Strings))
    error("Invalid string search: " + Name);
  return Iter->second;
}
// This function has some warts to it. There's a raw while loop and a
// reinterpret_cast.
void StringTableSection::initlize(
  const llvm::object::ELFFile<llvm::object::ELF64LE> & ElfFile,
  const llvm::object::ELF64LE::Shdr &Shdr) {
  ArrayRef<uint8_t> Data = unwrapOrError(ElfFile.getSectionContents(&Shdr));
  auto Iter = std::begin(Data);
  auto End = std::end(Data);
  while (Iter < End) {
    auto End = std::find(Iter, Data.end(), '\0');
    addString(StringRef(reinterpret_cast<const char *>(&*Iter), End - Iter));
    ++End;
    Iter = End;
  }
}
void StringTableSection::finalizeSize() {
  Size = 0;
  for (auto &Name : Strings) {
    Name.second = Size;
    // We need to add one on for the null character
    Size += Name.first.size() + 1;
  }
}

// Nothing needs to be done since finalizeSize was already called
void StringTableSection::finalize() {}

void StringTableSection::writeSection(FileOutputBuffer &Out) const {
  uint8_t *Buf = Out.getBufferStart() + Offset;
  for (const auto &Name : Strings) {
    Buf = std::copy(std::begin(Name.first), std::end(Name.first), Buf);
    // We need to set the null character and then increment the buffer past it
    *Buf = 0;
    Buf++;
  }
}

std::unique_ptr<SectionBase> Object::constructSection(Elf64_Word Type) {
  if (Type == SHT_STRTAB)
    return make_unique<StringTableSection>();
  return make_unique<Section>();
}

void Object::readProgramHeaders(const ELFFile<ELF64LE> &ElfFile) {
  uint32_t Index = 0;
  for (const auto &Phdr : unwrapOrError(ElfFile.program_headers())) {
    Segment Seg;
    Seg.Type = Phdr.p_type;
    Seg.Flags = Phdr.p_flags;
    Seg.Offset = Phdr.p_offset;
    Seg.VAddr = Phdr.p_vaddr;
    Seg.FileSize = Phdr.p_filesz;
    Seg.MemSize = Phdr.p_memsz;
    Seg.Align = Phdr.p_align;
    Seg.Index = Index;
    Index++;
    Segments.push_back(Seg);
  }
}

void Object::readSectionHeaders(const ELFFile<ELF64LE> &ElfFile) {
  Elf64_Word Index = 0;
  for (const auto &Shdr : unwrapOrError(ElfFile.sections())) {
    SecPtr Section = constructSection(Shdr.sh_type);
    Section->Name = unwrapOrError(ElfFile.getSectionName(&Shdr));
    Section->Type = Shdr.sh_type;
    Section->Flags = Shdr.sh_flags;
    Section->Addr = Shdr.sh_addr;
    Section->Offset = Shdr.sh_offset;
    Section->Size = Shdr.sh_size;
    Section->Link = Shdr.sh_link;
    Section->Info = Shdr.sh_info;
    Section->Align = Shdr.sh_addralign;
    Section->EntrySize = Shdr.sh_entsize;
    Section->Index = Index;
    Index++;
    Section->initlize(ElfFile, Shdr);
    for (auto &Phdr : Segments) {
      if (Phdr.Offset < Section->Offset &&
          Phdr.Offset + Phdr.FileSize > Section->Offset) {
        Phdr.addSection(&*Section);
        break;
      }
    }
    Sections.push_back(std::move(Section));
  }
}

size_t Object::totalSize() const {
  // We already have the section header offset so we can calculate the total
  // size by just adding up the size of each section header;
  return SHOffset + Sections.size() * sizeof(ELF64LE::Shdr);
}

Object::Object(const ELFObjectFile<ELF64LE> &Obj) {
  const auto &ElfFile = *Obj.getELFFile();
  const auto &Ehdr = *ElfFile.getHeader();

  std::copy(Ehdr.e_ident, Ehdr.e_ident + 16, Ident);
  Type = Ehdr.e_type;
  Machine = Ehdr.e_machine;
  Version = Ehdr.e_version;
  Entry = Ehdr.e_entry;
  Flags = Ehdr.e_flags;

  readProgramHeaders(ElfFile);
  readSectionHeaders(ElfFile);

  // If there is a .shstrtab section we have read it in by now. Now we want to
  // set the appropriete pointer.
  // TODO: make this using dyn_cast
  if (Ehdr.e_shstrndx != SHN_UNDEF)
    SectionNames = (StringTableSection *)&*Sections[Ehdr.e_shstrndx];
  else
    SectionNames = nullptr;
}

void Object::finalize() {
  // Put allocated sections first in address order.
  // Maintain ordering of previous non-allocated sections.
  auto CompareSections = [](const SecPtr &a, const SecPtr &b) {
    if (a->Flags & SHF_ALLOC) {
      if (b->Flags & SHF_ALLOC)
        return a->Addr < b->Addr;
      return true;
    }
    return a->Index < b->Index;
  };
  std::sort(std::begin(Sections), std::end(Sections), CompareSections);

  // Ungracefully handle an annoying optimization.
  for (const auto &Section : Sections) {
    // Sometimes a bit of string compression occurs on section names that reuse
    // part of a larger section name for a smaller section name. For instance
    // ".got.plt" can be used for the name index of ".got.plt" and ".plt".
    // The quickest fix for this is to add all the names before finalization.
    SectionNames->addString(Section->Name);
  }

  // The size of each section must be finalized before offsets and indexs can
  // be decided.
  for (auto &Section : Sections)
    Section->finalizeSize();

  // Decide file offsets and indexs
  size_t PhdrSize = Segments.size() * sizeof(ELF64LE::Phdr);
  // After the header and the program headers we can put section data.
  Elf64_Off Offset = sizeof(ELF64LE::Ehdr) + PhdrSize;
  Elf64_Word Index = 0;
  for (auto &Section : Sections) {
    Section->Offset = Offset;
    Section->Index = Index;
    if (Section->Type != SHT_NOBITS)
      Offset += Section->Size;
    Index++;
  }

  // 'offset' should now be just after all the section data so we should set the
  // section header table offset to be exactly here
  SHOffset = Offset;

  // If there is a SectionNames finalize it first so that we can assign name
  // indexes.
  if(SectionNames) SectionNames->finalize();

  // Finally now that all offsets and indexes have been set we can finalize any
  // reamining issues.
  for (auto &Section : Sections) {
    Section->HeaderOffset = Offset;
    Offset += sizeof(ELF64LE::Shdr);
    if(SectionNames)
      Section->NameIndex = SectionNames->findIndex(Section->Name);
    Section->finalize();
  }
}

void Object::writeHeader(FileOutputBuffer &Out) const {
  uint8_t *Buf = Out.getBufferStart();
  ELF64LE::Ehdr &Ehdr = *reinterpret_cast<ELF64LE::Ehdr *>(Buf);

  std::copy(Ident, Ident + 16, Ehdr.e_ident);
  Ehdr.e_type = Type;
  Ehdr.e_machine = Machine;
  Ehdr.e_version = Version;
  Ehdr.e_entry = Entry;
  Ehdr.e_phoff = sizeof(ELF64LE::Ehdr);
  Ehdr.e_shoff = SHOffset;
  Ehdr.e_flags = Flags;
  Ehdr.e_ehsize = sizeof(ELF64LE::Ehdr);
  Ehdr.e_phentsize = sizeof(ELF64LE::Phdr);
  Ehdr.e_phnum = Segments.size();
  Ehdr.e_shentsize = sizeof(ELF64LE::Shdr);
  Ehdr.e_shnum = Sections.size();
  Ehdr.e_shstrndx = SectionNames->Index;
}

void Object::writeProgramHeaders(FileOutputBuffer &Out) const {
  for (auto &Phdr : Segments)
    Phdr.writeHeader(Out);
}

void Object::writeSectionHeaders(FileOutputBuffer &Out) const {
  for (auto &Section : Sections)
    Section->writeHeader(Out);
}

void Object::writeSectionData(FileOutputBuffer &Out) const {
  for (auto &Section : Sections)
    Section->writeSection(Out);
}

void Object::write(FileOutputBuffer &Out) {
  writeHeader(Out);
  writeProgramHeaders(Out);
  writeSectionData(Out);
  writeSectionHeaders(Out);
}
