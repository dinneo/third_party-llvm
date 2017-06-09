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

template <class ELFT> void Segment::writeHeader(FileOutputBuffer &Out) const {
  uint8_t *Buf = Out.getBufferStart();
  Buf += sizeof(typename ELFT::Ehdr) + Index * sizeof(typename ELFT::Phdr);
  typename ELFT::Phdr &Phdr = *reinterpret_cast<typename ELFT::Phdr *>(Buf);
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

void SectionBase::finalize() {}

template <class ELFT>
void SectionBase::writeHeader(FileOutputBuffer &Out) const {
  uint8_t *Buf = Out.getBufferStart();
  Buf += HeaderOffset;
  typename ELFT::Shdr &Shdr = *reinterpret_cast<typename ELFT::Shdr *>(Buf);
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

void Section::writeSection(FileOutputBuffer &Out) const {
  uint8_t *Buf = Out.getBufferStart() + Offset;
  std::copy(std::begin(Contents), std::end(Contents), Buf);
}

void StringTableSection::addString(StringRef Name) {
  auto res = Strings.emplace(Name, 0);
  // We need to account for the null character as well
  if (res.second)
    Size += Name.size() + 1;
}

void StringTableSection::removeString(StringRef Name) {
  size_t count = Strings.erase(Name);
  // We need to account for the null character as well
  if (count)
    Size -= (Name.size() + 1);
}

uint32_t StringTableSection::findIndex(StringRef Name) const {
  auto Iter = Strings.find(Name);
  if (Iter == std::end(Strings))
    error("Invalid string search: " + Name);
  return Iter->second;
}

void StringTableSection::finalize() {
  uint32_t NameIndex = 0;
  for (auto &Name : Strings) {
    Name.second = NameIndex;
    NameIndex += Name.first.size() + 1;
  }
}

void StringTableSection::writeSection(FileOutputBuffer &Out) const {
  uint8_t *Buf = Out.getBufferStart() + Offset;
  for (const auto &Name : Strings) {
    Buf = std::copy(std::begin(Name.first), std::end(Name.first), Buf);
    // We need to set the null character and then increment the buffer past it
    *Buf = 0;
    Buf++;
  }
}

template <class ELFT>
void Object<ELFT>::readProgramHeaders(const ELFFile<ELFT> &ElfFile) {
  uint32_t Index = 0;
  for (const auto &Phdr : unwrapOrError(ElfFile.program_headers())) {
    Segments.emplace_back();
    Segment &Seg = Segments.back();
    Seg.Type = Phdr.p_type;
    Seg.Flags = Phdr.p_flags;
    Seg.Offset = Phdr.p_offset;
    Seg.VAddr = Phdr.p_vaddr;
    Seg.FileSize = Phdr.p_filesz;
    Seg.MemSize = Phdr.p_memsz;
    Seg.Align = Phdr.p_align;
    Seg.Index = Index;
    Index++;
    for (auto &Section : Sections) {
      if (Seg.Offset <= Section->Offset &&
          Seg.Offset + Seg.FileSize >= Section->Offset + Section->Size) {
        Seg.addSection(&*Section);
        Section->ParrentSegment = &Seg;
      }
    }
  }
}

template <class ELFT>
void Object<ELFT>::readSectionHeaders(const ELFFile<ELFT> &ElfFile) {
  uint32_t Index = 0;
  for (const auto &Shdr : unwrapOrError(ElfFile.sections())) {
    if (Shdr.sh_type == SHT_STRTAB)
      continue;
    ArrayRef<uint8_t> Data = unwrapOrError(ElfFile.getSectionContents(&Shdr));
    SecPtr Sec = make_unique<Section>(Data);
    Sec->Name = unwrapOrError(ElfFile.getSectionName(&Shdr));
    Sec->Type = Shdr.sh_type;
    Sec->Flags = Shdr.sh_flags;
    Sec->Addr = Shdr.sh_addr;
    Sec->Offset = Shdr.sh_offset;
    Sec->Size = Shdr.sh_size;
    Sec->Link = Shdr.sh_link;
    Sec->Info = Shdr.sh_info;
    Sec->Align = Shdr.sh_addralign;
    Sec->EntrySize = Shdr.sh_entsize;
    Sec->Index = Index;
    Index++;
    SectionNames->addString(Sec->Name);
    Sections.push_back(std::move(Sec));
  }
}

template <class ELFT> size_t Object<ELFT>::totalSize() const {
  // We already have the section header offset so we can calculate the total
  // size by just adding up the size of each section header;
  return SHOffset + Sections.size() * sizeof(typename ELFT::Shdr);
}

template <class ELFT> Object<ELFT>::Object(const ELFObjectFile<ELFT> &Obj) {
  const auto &ElfFile = *Obj.getELFFile();
  const auto &Ehdr = *ElfFile.getHeader();

  std::copy(Ehdr.e_ident, Ehdr.e_ident + 16, Ident);
  Type = Ehdr.e_type;
  Machine = Ehdr.e_machine;
  Version = Ehdr.e_version;
  Entry = Ehdr.e_entry;
  Flags = Ehdr.e_flags;
  SectionNames = new StringTableSection();
  SectionNames->Name = ".shstrtab";
  SectionNames->addString(SectionNames->Name);
  Sections.emplace_back(SectionNames);

  readSectionHeaders(ElfFile);
  readProgramHeaders(ElfFile);
}

template <class ELFT> void Object<ELFT>::sortSections() {
  // Put allocated sections in address order. Maintain ordering as closely as
  // possible while meeting that demand however.
  auto CompareSections = [](const SecPtr &a, const SecPtr &b) {
    if (a->Type == SHT_NULL)
      return true;
    if (a->Flags & SHF_ALLOC && b->Flags & SHF_ALLOC)
      return a->Addr < b->Addr;
    return a->Index < b->Index;
  };
  std::sort(std::begin(Sections), std::end(Sections), CompareSections);
}

uint64_t align(uint64_t value, uint64_t multiple) {
  if (!multiple || value % multiple == 0)
    return value;
  return value + multiple - value % multiple;
}

template <class ELFT> void Object<ELFT>::assignOffsets() {
  // Decide file offsets and indexs
  size_t PhdrSize = Segments.size() * sizeof(typename ELFT::Phdr);
  // After the header and the program headers we can put section data.
  uint64_t Offset = sizeof(typename ELFT::Ehdr) + PhdrSize;
  uint64_t Index = 0;
  for (auto &Section : Sections) {
    // The segment can have a different alignment than the section. We need to
    // make sure
    if (Section->ParrentSegment) {
      auto FirstInSeg = Section->ParrentSegment->firstSection();
      if (FirstInSeg == Section.get())
        Offset = align(Offset, Section->ParrentSegment->Align);
    }
    Offset = align(Offset, Section->Align);
    Section->Offset = Offset;
    Section->Index = Index;
    if (Section->Type != SHT_NOBITS)
      Offset += Section->Size;
    Index++;
  }
  // 'offset' should now be just after all the section data so we should set the
  // section header table offset to be exactly here. This spot might not be
  // aligned properlly however so we should align it as needed. This only takes
  // a little bit of tweaking to ensure that the sh_name is 4 byte aligned
  Offset += 4 - Offset % 4;
  SHOffset = Offset;
}

template <class ELFT> void Object<ELFT>::finalize() {
  sortSections();
  assignOffsets();

  // finalize SectionNames first so that we can assign name indexes.
  SectionNames->finalize();
  // Finally now that all offsets and indexes have been set we can finalize any
  // reamining issues.
  uint64_t Offset = SHOffset;
  for (auto &Section : Sections) {
    Section->HeaderOffset = Offset;
    Offset += sizeof(typename ELFT::Shdr);
    Section->NameIndex = SectionNames->findIndex(Section->Name);
    Section->finalize();
  }

  for (auto &Segment : Segments)
    Segment.finalize();
}

template <class ELFT>
void Object<ELFT>::writeHeader(FileOutputBuffer &Out) const {
  uint8_t *Buf = Out.getBufferStart();
  typename ELFT::Ehdr &Ehdr = *reinterpret_cast<typename ELFT::Ehdr *>(Buf);
  std::copy(Ident, Ident + 16, Ehdr.e_ident);
  Ehdr.e_type = Type;
  Ehdr.e_machine = Machine;
  Ehdr.e_version = Version;
  Ehdr.e_entry = Entry;
  Ehdr.e_phoff = sizeof(typename ELFT::Ehdr);
  Ehdr.e_shoff = SHOffset;
  Ehdr.e_flags = Flags;
  Ehdr.e_ehsize = sizeof(typename ELFT::Ehdr);
  Ehdr.e_phentsize = sizeof(typename ELFT::Phdr);
  Ehdr.e_phnum = Segments.size();
  Ehdr.e_shentsize = sizeof(typename ELFT::Shdr);
  Ehdr.e_shnum = Sections.size();
  Ehdr.e_shstrndx = SectionNames->Index;
}

template <class ELFT>
void Object<ELFT>::writeProgramHeaders(FileOutputBuffer &Out) const {
  for (auto &Phdr : Segments)
    Phdr.template writeHeader<ELFT>(Out);
}

template <class ELFT>
void Object<ELFT>::writeSectionHeaders(FileOutputBuffer &Out) const {
  for (auto &Section : Sections)
    Section->template writeHeader<ELFT>(Out);
}

template <class ELFT>
void Object<ELFT>::writeSectionData(FileOutputBuffer &Out) const {
  for (auto &Section : Sections)
    Section->writeSection(Out);
}

template <class ELFT> void Object<ELFT>::write(FileOutputBuffer &Out) {
  writeHeader(Out);
  writeProgramHeaders(Out);
  writeSectionData(Out);
  writeSectionHeaders(Out);
}

template class Object<ELF64LE>;
template class Object<ELF64BE>;
template class Object<ELF32LE>;
template class Object<ELF32BE>;
