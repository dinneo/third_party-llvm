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

uint64_t align(uint64_t Value, uint64_t Multiple) {
  if (!Multiple || Value % Multiple == 0)
    return Value;
  return Value + Multiple - Value % Multiple;
}

template <class ELFT> void Segment::writeHeader(uint8_t *Buf) const {
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
  auto MinElem = firstSection();
  if (!MinElem)
    return;
  if (Type == PT_LOAD) {
    auto PrevSection = MinElem;
    for (auto Sec : Sections) {
      if (Sec->Addr > PrevSection->Addr + PrevSection->Size) {
        // Then we have a gap which we can expect file layout to respect. We
        // need to respect the contents of this gap as well as the user may have
        // put something meanigful in them like trap instructions in the case
        // that this segment is executable.
        ArrayRef<uint8_t> InterstitialData{Contents.data() + PrevSection->Addr -
                                               VAddr + PrevSection->Size,
                                           Contents.data() + Sec->Addr - VAddr};
        auto InterstitialSection = new Section(InterstitialData);
        InterstitialSection->Addr = PrevSection->Addr + PrevSection->Size;
        InterstitialSections.emplace_back(InterstitialSection);
      }
      PrevSection = Sec;
    }
    // Lastly there might be an interstitial gap between the last section and
    // the end of the segment.
    if (VAddr + MemSize > PrevSection->Addr + PrevSection->Size) {
      ArrayRef<uint8_t> InterstitialData{Contents.data() + PrevSection->Addr -
                                             VAddr + PrevSection->Size,
                                         Contents.data() + MemSize};
      auto InterstitialSection = new Section(InterstitialData);
      InterstitialSection->Addr = PrevSection->Addr + PrevSection->Size;
      InterstitialSections.emplace_back(InterstitialSection);
    }
    for (auto &InterstitialSection : InterstitialSections)
      Sections.insert(InterstitialSection.get());
  }

  // In practice you could have a section that contained no sections. In this
  // case the file offset is meaingless. Other aspects of it can still hold
  // meaning however so we want to preserve those things still. So if there is
  // no MinElem we just leave Offset as it was in the file.
  if (MinElem)
    Offset = MinElem->Offset;
}

void Segment::writeMemSegment(uint8_t *Buf) const {
  // Because we have filled in all gaps with interstitial sections we can be
  // sure that we will cover the entire size of MemSize
  for (auto Section : Sections) {
    Section->writeSection(Buf);
    Buf += Section->Size;
  }
}

void SectionBase::finalize() {}

template <class ELFT> void SectionBase::writeHeader(uint8_t *Buf) const {
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

void Section::writeSection(uint8_t *Buf) const {
  std::copy(std::begin(Contents), std::end(Contents), Buf);
}

void StringTableSection::addString(StringRef Name) {
  auto res = Strings.insert(std::make_pair(Name, 0));
  // We need to account for the null character as well
  if (res.second)
    Size += Name.size() + 1;
}

void StringTableSection::removeString(StringRef Name) {
  size_t Count = Strings.erase(Name);
  // We need to account for the null character as well
  if (Count)
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
    Name.getValue() = NameIndex;
    NameIndex += Name.getKey().size() + 1;
  }
}

void StringTableSection::writeSection(uint8_t *Buf) const {
  for (const auto &Name : Strings) {
    Buf = std::copy(std::begin(Name.getKey()), std::end(Name.getKey()), Buf);
    // We need to set the null character and then increment the buffer past it
    *Buf = 0;
    Buf++;
  }
}

template <class ELFT>
void SymbolTableSection<ELFT>::addSymbol(StringRef Name, uint8_t Bind,
                                         uint8_t Type, SectionBase *DefinedIn,
                                         uint64_t Value, uint64_t Sz) {
  Symbol Sym;
  Sym.Name = Name;
  Sym.Binding = Bind;
  Sym.Type = Type;
  Sym.DefinedIn = DefinedIn;
  Sym.Value = Value;
  Sym.Size = Sz;
  Sym.Index = Symbols.size();
  auto Res = Symbols.insert(std::make_pair(Name, Sym));
  if (Res.second)
    Size += sizeof(typename ELFT::Sym);
  SymbolNames.addString(Name);
}

template <class ELFT>
void SymbolTableSection<ELFT>::removeSymbol(StringRef Name) {
  auto Iter = Symbols.find(Name);
  if (Iter != std::end(Symbols)) {
    Symbols.erase(Iter);
    Size += sizeof(ELFT::Sym);
  }
  SymbolNames.removeString(Name);
}

template <class ELFT> void SymbolTableSection<ELFT>::finalize() {
  auto CompareBinding = [](const Symbol &a, const Symbol &b) {
    return a.Binding < b.Binding;
  };
  auto CompareIndex = [](const Symbol &a, const Symbol &b) {
    return a.Index < b.Index;
  };
  // Make sure that SymbolNames is finalized first
  SymbolNames.finalize();
  for (auto &Entry : Symbols) {
    Entry.second.NameIndex = SymbolNames.findIndex(Entry.second.Name);
    FinalSymbols.push_back(Entry.second);
  }
  Symbol DummyLocal;
  DummyLocal.Binding = STB_LOCAL;
  std::sort(std::begin(FinalSymbols), std::end(FinalSymbols), CompareIndex);
  std::stable_sort(std::begin(FinalSymbols), std::end(FinalSymbols),
                   CompareBinding);
  auto Iter = std::upper_bound(std::begin(FinalSymbols), std::end(FinalSymbols),
                               DummyLocal, CompareBinding);
  Info = std::end(FinalSymbols) - Iter;
  Link = SymbolNames.Index;
}

template <class ELFT>
void SymbolTableSection<ELFT>::writeSection(uint8_t *Buf) const {
  typename ELFT::Sym *Sym = reinterpret_cast<typename ELFT::Sym *>(Buf);

  for(auto &Symbol : FinalSymbols) {
    Sym->st_name = Symbol.NameIndex;
    Sym->st_value = Symbol.Value;
    Sym->st_size = Symbol.Size;
    Sym->setBinding(Symbol.Binding);
    Sym->setType(Symbol.Type);
    if(Symbol.DefinedIn)
      Sym->st_shndx = Symbol.DefinedIn->Index;
    else
      Sym->st_shndx = SHN_UNDEF;
    ++Sym;
  }
}

template <class ELFT>
void ObjectCopyBase<ELFT>::readProgramHeaders(const ELFFile<ELFT> &ElfFile) {
  uint32_t Index = 0;
  for (const auto &Phdr : unwrapOrError(ElfFile.program_headers())) {
    ArrayRef<uint8_t> Data{ElfFile.base() + Phdr.p_offset, Phdr.p_filesz};
    Segments.emplace_back(Data);
    Segment &Seg = Segments.back();
    Seg.Type = Phdr.p_type;
    Seg.Flags = Phdr.p_flags;
    Seg.Offset = Phdr.p_offset;
    Seg.VAddr = Phdr.p_vaddr;
    Seg.FileSize = Phdr.p_filesz;
    Seg.MemSize = Phdr.p_memsz;
    Seg.Align = Phdr.p_align;
    Seg.Index = Index++;
    for (auto &Section : Sections) {
      if (Seg.Offset <= Section->Offset &&
          Seg.Offset + Seg.FileSize >= Section->Offset + Section->Size &&
          (Section->Flags & SHF_ALLOC)) {
        Section->ParrentSegment = &Seg;
        Seg.addSection(Section.get());
      }
    }
  }
}

template <class ELFT>
void ObjectCopyBase<ELFT>::readSymbolTable(const ELFFile<ELFT> &ElfFile,
                                           const Elf_Shdr &SymTabShdr) {

  StringTableSection *StrTab =
      dyn_cast<StringTableSection>(Sections[SymTabShdr.sh_link].get());

  uint32_t SymTabIndex =
      &SymTabShdr - unwrapOrError(ElfFile.sections()).begin();

  SymbolTable = new SymbolTableSection<ELFT>(*StrTab);
  SymbolTable->Name = unwrapOrError(ElfFile.getSectionName(&SymTabShdr));
  SymbolTable->Index = SymTabIndex;
  SectionNames->addString(SymbolTable->Name);

  StringRef StrTabData =
      unwrapOrError(ElfFile.getStringTableForSymtab(SymTabShdr));

  for (const auto &Sym : unwrapOrError(ElfFile.symbols(&SymTabShdr))) {
    SectionBase *DefSection = nullptr;
    if (Sym.st_shndx != SHN_UNDEF)
      DefSection = Sections[Sym.st_shndx].get();
    StringRef Name = unwrapOrError(Sym.getName(StrTabData));
    SymbolTable->addSymbol(Name, Sym.getBinding(), Sym.getType(), DefSection,
                           Sym.getValue(), Sym.st_size);
  }
  // Calculate where the SymbolTable belongs
  Sections[SymTabIndex].reset(SymbolTable);
}

template <class ELFT>
static std::unique_ptr<SectionBase> makeSection(ArrayRef<uint8_t> Data,
                                                uint64_t Type) {
  if (Type == SHT_STRTAB)
    return make_unique<StringTableSection>();
  return make_unique<Section>(Data);
}

template <class ELFT>
void ObjectCopyBase<ELFT>::readSectionHeaders(const ELFFile<ELFT> &ElfFile) {
  uint32_t Index = 0;
  const Elf_Shdr *SymTabShdr = nullptr;
  for (const auto &Shdr : unwrapOrError(ElfFile.sections())) {
    if (Index == SectionNames->Index) {
      Sections.emplace_back(SectionNames);
      Index++;
      continue;
    }
    if (Shdr.sh_type == SHT_SYMTAB) {
      // Put a placeholder in Sections so that Index corrasponds to the
      // location in the array the symbol table should go
      Sections.emplace_back(nullptr);
      SymTabShdr = &Shdr;
      Index++;
      continue;
    }
    ArrayRef<uint8_t> Data = unwrapOrError(ElfFile.getSectionContents(&Shdr));
    SecPtr Sec = makeSection<ELFT>(Data, Shdr.sh_type);
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
    Sec->Index = Index++;
    SectionNames->addString(Sec->Name);
    Sections.push_back(std::move(Sec));
  }
  // If we encountered a symbol table construct it now that we should have
  // every section
  if (SymTabShdr)
    readSymbolTable(ElfFile, *SymTabShdr);
}

template <class ELFT>
ObjectCopyBase<ELFT>::ObjectCopyBase(const ELFObjectFile<ELFT> &Obj) {
  const auto &ElfFile = *Obj.getELFFile();
  const auto &Ehdr = *ElfFile.getHeader();

  std::copy(Ehdr.e_ident, Ehdr.e_ident + 16, Ident);
  Type = Ehdr.e_type;
  Machine = Ehdr.e_machine;
  Version = Ehdr.e_version;
  Entry = Ehdr.e_entry;
  Flags = Ehdr.e_flags;

  SectionNames = new StringTableSection();
  auto Shdr = unwrapOrError(ElfFile.getSection(Ehdr.e_shstrndx));
  SectionNames->Name = unwrapOrError(ElfFile.getSectionName(Shdr));
  SectionNames->Index = Ehdr.e_shstrndx;
  SectionNames->addString(SectionNames->Name);

  readSectionHeaders(ElfFile);
  readProgramHeaders(ElfFile);
}

template <class ELFT> size_t ObjectCopyELF<ELFT>::totalSize() const {
  // We already have the section header offset so we can calculate the total
  // size by just adding up the size of each section header;
  return this->SHOffset + this->Sections.size() * sizeof(Elf_Shdr);
}

template <class ELFT> void ObjectCopyELF<ELFT>::sortSections() {
  std::sort(
      std::begin(this->Sections), std::end(this->Sections),
      [](const SecPtr &A, const SecPtr &B) { return A->Index < B->Index; });
}

template <class ELFT> void ObjectCopyELF<ELFT>::assignOffsets() {
  // Decide file offsets and indexs
  size_t PhdrSize = this->Segments.size() * sizeof(Elf_Phdr);
  // After the header and the program headers we can put section data.
  uint64_t Offset = sizeof(Elf_Ehdr) + PhdrSize;
  uint64_t Index = 0;
  for (auto &Section : this->Sections) {
    // The segment can have a different alignment than the section. We need to
    // make sure
    if (Section->ParrentSegment) {
      auto FirstInSeg = Section->ParrentSegment->firstSection();
      if (FirstInSeg == Section.get())
        Offset = align(Offset, Section->ParrentSegment->Align);
      // We should respect interstitial gaps of allocated sections
      Offset = FirstInSeg->Offset + Section->Addr - FirstInSeg->Addr;
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
  Offset = align(Offset, sizeof(typename ELFT::Word));
  this->SHOffset = Offset;
}

template <class ELFT> void ObjectCopyELF<ELFT>::finalize() {
  sortSections();
  assignOffsets();

  // finalize SectionNames first so that we can assign name indexes.
  this->SectionNames->finalize();

  // Finally now that all offsets and indexes have been set we can finalize any
  // reamining issues.
  for (auto &Section : this->Sections) {
    Section->NameIndex = this->SectionNames->findIndex(Section->Name);
    Section->finalize();
  }

  for (auto &Segment : this->Segments)
    Segment.finalize();
}

template <class ELFT>
void ObjectCopyELF<ELFT>::writeHeader(FileOutputBuffer &Out) const {
  uint8_t *Buf = Out.getBufferStart();
  typename ELFT::Ehdr &Ehdr = *reinterpret_cast<typename ELFT::Ehdr *>(Buf);
  std::copy(this->Ident, this->Ident + 16, Ehdr.e_ident);
  Ehdr.e_type = this->Type;
  Ehdr.e_machine = this->Machine;
  Ehdr.e_version = this->Version;
  Ehdr.e_entry = this->Entry;
  Ehdr.e_phoff = sizeof(Elf_Ehdr);
  Ehdr.e_shoff = this->SHOffset;
  Ehdr.e_flags = this->Flags;
  Ehdr.e_ehsize = sizeof(Elf_Ehdr);
  Ehdr.e_phentsize = sizeof(Elf_Phdr);
  Ehdr.e_phnum = this->Segments.size();
  Ehdr.e_shentsize = sizeof(Elf_Shdr);
  Ehdr.e_shnum = this->Sections.size();
  Ehdr.e_shstrndx = this->SectionNames->Index;
}

template <class ELFT>
void ObjectCopyELF<ELFT>::writeProgramHeaders(FileOutputBuffer &Out) const {
  uint8_t *Buf = Out.getBufferStart() + sizeof(Elf_Ehdr);
  for (auto &Segment : this->Segments) {
    Segment.template writeHeader<ELFT>(Buf);
    Buf += sizeof(Elf_Phdr);
  }
}

template <class ELFT>
void ObjectCopyELF<ELFT>::writeSectionHeaders(FileOutputBuffer &Out) const {
  uint8_t *Buf = Out.getBufferStart() + this->SHOffset;
  for (auto &Section : this->Sections) {
    Section->template writeHeader<ELFT>(Buf);
    Buf += sizeof(Elf_Shdr);
  }
}

template <class ELFT>
void ObjectCopyELF<ELFT>::writeSectionData(FileOutputBuffer &Out) const {
  uint8_t *Buf = Out.getBufferStart();
  for (auto &Section : this->Sections) {
    Section->writeSection(Buf + Section->Offset);
  }
}

template <class ELFT>
void ObjectCopyELF<ELFT>::write(FileOutputBuffer &Out) const {
  writeHeader(Out);
  writeProgramHeaders(Out);
  writeSectionData(Out);
  writeSectionHeaders(Out);
}

template <class ELFT> void ObjectCopyBinary<ELFT>::finalize() {
  for (auto &Segment : this->Segments)
    Segment.finalize();
}

template <class ELFT> size_t ObjectCopyBinary<ELFT>::totalSize() const {
  uint64_t BinSize = 0;
  for (auto &Segment : this->Segments) {
    if (Segment.Type == PT_LOAD && Segment.Offset != 0) {
      BinSize = align(BinSize, Segment.Align);
      BinSize += Segment.FileSize;
    }
  }
  return BinSize;
}

template <class ELFT>
void ObjectCopyBinary<ELFT>::write(FileOutputBuffer &Out) const {
  // It's worth noting that Segments might be put in very different locations
  // from each other. They will still be placed
  uint8_t *Buf = Out.getBufferStart();
  uint64_t Offset = 0;
  for (auto &Segment : this->Segments) {
    if (Segment.Type == PT_LOAD && Segment.Offset != 0) {
      Offset = align(Offset, Segment.Align);
      Segment.writeMemSegment(Buf + Offset);
      Offset += Segment.FileSize;
    }
  }
}

template class ObjectCopyELF<ELF64LE>;
template class ObjectCopyELF<ELF64BE>;
template class ObjectCopyELF<ELF32LE>;
template class ObjectCopyELF<ELF32BE>;

template class ObjectCopyBinary<ELF64LE>;
template class ObjectCopyBinary<ELF64BE>;
template class ObjectCopyBinary<ELF32LE>;
template class ObjectCopyBinary<ELF32BE>;
