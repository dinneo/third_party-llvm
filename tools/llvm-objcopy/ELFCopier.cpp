//===- ELFCopy.cpp --------------------------------------------------------===//
//
//                             The LLVM Linker
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "ObjCopier.h"

#include "llvm/Object/ELF.h"
#include "llvm/Object/ELFObjectFile.h"
#include "llvm/Support/Endian.h"
#include "llvm/Support/FileOutputBuffer.h"

using namespace llvm;
using namespace llvm::object;
using namespace ELF;

struct Section;

struct FileHeader {
  uint8_t Class;
  uint8_t Data;
  uint8_t OSABI;
  uint16_t Type;
  uint32_t Machine;
  uint64_t Flags;
};

struct ProgramHeader {
  ProgramHeader();
  void add(Section *Sec);

  uint32_t Type = 0;
  uint64_t Offset = 0;
  uint64_t VMA = 0;
  uint64_t LMA = 0;
  uint64_t FileSz = 0;
  uint64_t MemSz = 0;
  uint32_t Flags = 0;
  uint32_t Align = 0;

  std::vector<Section *> Sections;

  Section *First = nullptr;
  Section *Last = nullptr;
};

struct Section {
  StringRef Name;
  uint32_t Alignment;
  uint64_t Flags;
  uint32_t Type;
  uint64_t Offset = 0;
  uint64_t Entsize;
  uint64_t Addr;
  uint64_t Size;
  /* StringRef? */ uint32_t Link;
  /* StringRef? */uint32_t Info;
  
  ArrayRef<uint8_t> Data;
};

struct Symbol {
  StringRef Name;
  uint8_t Type;
  uint64_t Value;
  uint64_t Size;
  uint8_t Other;

  Section *Section;
};

struct Relocation {
  uint64_t Offset;
  int64_t Addend;
  uint32_t Type;
  StringRef Symbol;
};

struct Object {
  FileHeader Header;
  std::vector<std::unique_ptr<ProgramHeader>> ProgramHeaders;
  std::vector<std::unique_ptr<Section>> Sections;
  struct Symbols {
    std::vector<Symbol> Local;
    std::vector<Symbol> Global;
    std::vector<Symbol> Weak;
  };
};

template<typename ELFT>
class ELFCopier : public ObjCopier {
  typedef typename object::ELFFile<ELFT>::Elf_Ehdr Elf_Ehdr;
  typedef typename object::ELFFile<ELFT>::Elf_Shdr Elf_Shdr;
  typedef typename object::ELFFile<ELFT>::Elf_Sym Elf_Sym;
  typedef typename object::ELFFile<ELFT>::Elf_Rel Elf_Rel;
  typedef typename object::ELFFile<ELFT>::Elf_Rela Elf_Rela;

public:
  ELFCopier(const ELFFile<ELFT> *Obj, std::unique_ptr<FileOutputBuffer> Buffer);

  std::vector<ProgramHeader> ProgramHeaders;
  std::vector<Section> Sections;

private:
  ELFFile<ELFT> *Obj;
};

template <typename ELFT>
ELFCopier<ELFT>::ELFCopier(const ELFFile<ELFT> *Obj, std::unique_ptr<FileOutputBuffer> Buffer)
    : ObjCopier(Buffer), Obj(Obj) {
}

template <typename ELFT>
void ELFCopier<ELFT>::readPhdr() {
  const Elf_Ehdr *Header = Obj->getHeader();
  for (const Elf_Phdr &Phdr : unwrapOrError(Obj->program_headers()) {
    ProgramHeader P;
    P.Type = Phdr.p_type;
    P.Offset = Phdr.p_offset;
    P.VMA = Phdr.p_vaddr;
    P.LMA = Phdr.p_paddr;
    P.FileSz = Phdr.p_filesz;
    P.MemSz = Phdr.p_memsz;
    P.Flags = Phdr.p_flags;
    P.Align = Phdr.p_align;
    ProgramHeaders.push_back(P);
  }
}

// SHF_TLS sections are only in PT_TLS, PT_LOAD or PT_GNU_RELRO
// PT_TLS must only have SHF_TLS sections
template <class ELFT>
bool checkTLSSections(const Elf_Phdr &Phdr, const Elf_Shdr &Shdr) {
  return (((Shdr.sh_flags & ELF::SHF_TLS) &&
           ((Phdr.p_type == ELF::PT_TLS) || (Phdr.p_type == ELF::PT_LOAD) ||
            (Phdr.p_type == ELF::PT_GNU_RELRO))) ||
          (!(Shdr.sh_flags & ELF::SHF_TLS) && Phdr.p_type != ELF::PT_TLS));
}

// Non-SHT_NOBITS must have its offset inside the segment
// Only non-zero section can be at end of segment
template <class ELFT>
static bool checkoffsets(const Elf_Phdr &Phdr, const Elf_Shdr &Shdr) {
  if (Shdr.sh_type == ELF::SHT_NOBITS)
    return true;
  bool IsSpecial =
      (Shdr.sh_type == ELF::SHT_NOBITS) && ((Shdr.sh_flags & ELF::SHF_TLS) != 0);
  // .tbss is special, it only has memory in PT_TLS and has NOBITS properties
  auto SectionSize =
      (IsSpecial && Phdr.p_type != ELF::PT_TLS) ? 0 : Shdr.sh_size;
  if (Shdr.sh_offset >= Phdr.p_offset)
    return ((Shdr.sh_offset + SectionSize <= Phdr.p_filesz + Phdr.p_offset)
            /*only non-zero sized sections at end*/ &&
            (Shdr.sh_offset + 1 <= Phdr.p_offset + Phdr.p_filesz));
  return false;
}

// SHF_ALLOC must have VMA inside segment
// Only non-zero section can be at end of segment
template <class ELFT>
static bool checkVMA(const Elf_Phdr &Phdr, const Elf_Shdr &Shdr) {
  if (!(Shdr.sh_flags & ELF::SHF_ALLOC))
    return true;
  bool IsSpecial =
      (Shdr.sh_type == ELF::SHT_NOBITS) && ((Shdr.sh_flags & ELF::SHF_TLS) != 0);
  // .tbss is special, it only has memory in PT_TLS and has NOBITS properties
  auto SectionSize =
      (IsSpecial && Phdr.p_type != ELF::PT_TLS) ? 0 : Shdr.sh_size;
  if (Shdr.sh_addr >= Phdr.p_vaddr)
    return ((Shdr.sh_addr + SectionSize <= Phdr.p_vaddr + Phdr.p_memsz) &&
            (Shdr.sh_addr + 1 <= Phdr.p_vaddr + Phdr.p_memsz));
  return false;
}

// No section with zero size must be at start or end of PT_DYNAMIC
template <class ELFT>
static bool checkPTDynamic(const Elf_Phdr &Phdr, const Elf_Shdr &Shdr) {
  if (Phdr.p_type != ELF::PT_DYNAMIC || Shdr.sh_size != 0 || Phdr.p_memsz == 0)
    return true;
  // Is section within the phdr both based on offset and VMA ?
  return ((Shdr.sh_type == ELF::SHT_NOBITS) ||
          (Shdr.sh_offset > Phdr.p_offset &&
           Shdr.sh_offset < Phdr.p_offset + Phdr.p_filesz)) &&
         (!(Shdr.sh_flags & ELF::SHF_ALLOC) ||
          (Shdr.sh_addr > Phdr.p_vaddr && Shdr.sh_addr < Phdr.p_memsz));
}

void ELFCopier<ELFT>::sections() {
  for (const Elf_Shdr &Shdr : unwrapOrError(Obj->sections())) {
    Section S;
    S.Name = unwrapOrError(Obj->getSectionName(Shdr));
    S.Flags = Shdr.sh_flags;
    S.Type = Shdr.sh_type;
    S.Entsize = Shdr.sh_entsize;
    S.Alignment = Shdr.sh_addralign;
    S.Offset = Shdr.sh_offset;
    S.Size = Shdr.sh_size;
    S.Addr = Shdr.sh_addr;
    S.Info = Shdr.sh_info;
    S.Link = Shdr.sh_link;
    S.Contents = Obj->getSectionContents(Shdr);
    Sections.push_back(S);

    for (auto &P : ProgramHeaders) {
      if (checkOffsets(Phdr, Shdr) && checkVMA(Phdr, Shdr)) {
        P.add(S);
      }
    }
  }
}

template <typename ELFT>
void ELFCopier<ELFT>::copy() {
  uint8_t *Buf = Buffer->getBufferStart();
  memcpy(Buf, "\177ELF", 4);

  // Copy the ELF header.
  auto *IE = Obj->getHeader();
  auto *Ehdr = reinterpret_cast<Elf_Ehdr *>(Buf);
  Ehdr->e_ident[EI_CLASS] = IE->e_ident[EI_CLASS];
  Ehdr->e_ident[EI_DATA] = IE->e_ident[EI_DATA];
  Ehdr->e_ident[EI_VERSION] = IE->e_ident[EI_VERSION];
  Ehdr->e_ident[EI_OSABI] = IE->e_ident[EI_OSABI];
  Ehdr->e_ident[EI_ABIVERSION] = IE->e_ident[EI_ABIVERSION];
  Ehdr->e_type = IE->e_type;
  Ehdr->e_machine = IE->e_machine;
  Ehdr->e_version = IE->e_version;
  Ehdr->e_entry = IE->e_entry;
  Ehdr->e_flags = IE->e_flags;
  EHdr->e_shoff = SectionHeaderOff;
  
  //EHdr->e_ehsize = sizeof(Elf_Ehdr);
  //EHdr->e_phnum = Phdrs.size();
  //EHdr->e_shentsize = sizeof(Elf_Shdr);
  //EHdr->e_shnum = OutputSections.size() + 1;
  //EHdr->e_shstrndx = In<ELFT>::ShStrTab->OutSec->SectionIndex;

  //if (!(IE->e_type & ET_REL)) {
  //  OE->e_phoff = sizeof(Elf_Ehdr);
  //  OE->e_phentsize = sizeof(Elf_Phdr);
  //}

  // Write the program header table
  auto *Phdrs = reinterpret_cast<Elf_Phdr *>(Buf + OE->e_phoff);
  for (auto &P : ProgramHeaders) {
    Elf_Phdr *Phdr = Phdrs;
    Phdr->p_type = P.Type;
    Phdr->p_flags = P.Flags;
    Phdr->p_offset = P.Offset;
    Phdr->p_vaddr = P.VMA;
    Phdr->p_paddr = P.LMA;
    Phdr->p_filesz = P.FileSz;
    Phdr->p_memsz = P.MemSz;
    Phdr->p_align = P.Align;
    ++Phdrs;
  }

  // Write the program section header table
  auto *Shdrs = reinterpret_cast<Elf_Shdr *>(Buf + OE->e_shoff);
  for (auto &S : Sections) {
    Elf_Shdr *Shdr = ++Shdrs;
    Shdr->sh_entsize = S.Entsize;
    Shdr->sh_addralign = S.Alignment;
    Shdr->sh_type = S.Type;
    Shdr->sh_offset = S.Offset;
    Shdr->sh_flags = S.Flags;
    Shdr->sh_info = S.Info;
    Shdr->sh_link = S.Link;
    Shdr->sh_addr = S.Addr;
    Shdr->sh_size = S.Size;
  }
}

#if 0
template <class ELFT> void ELFCopier<ELFT>::writeHeader() {
  uint8_t *Buf = Buffer->getBufferStart();
  memcpy(Buf, "\177ELF", 4);
}

template <class ELFT>
void copyELF(const ELFObjectFile<ELFT> *Obj, std::unique_ptr<tool_output_file> &Out) {
  std::error_code EC;
  Out->os().write("\177ELF", 4);
  const ELFFile<ELFT> *File = Obj->getELFFile();

  for (const auto &Section : Obj->sections()) {
  //for (const SectionRef &Section : ToolSectionFilter(*Obj)) {
    StringRef Name;
    uint64_t Addr = Section.getAddress();

    //if (Addr != Val)
    //  continue;
    StringRef BytesStr;
    Section.getContents(BytesStr);
    ArrayRef<uint8_t> Bytes(reinterpret_cast<const uint8_t *>(BytesStr.data()),
                            BytesStr.size());

    if ((EC = Section.getName(Name)))
      report_fatal_error(EC.message());
    llvm::outs() << Name << " (" << Section.getAddress() << ", " << Section.getSize() << ")\n";

    for (uint64_t addr = 0, end = BytesStr.size(); addr < end; addr++)
      Out->os() << BytesStr[addr];
  }

  Out->keep();
}
#endif

namespace llvm {

template<class ELFT>
static std::error_code createELFCopier(const ELFFile<ELFT> *Obj,
                                       std::unique_ptr<tool_output_file> Out,
                                       std::unique_ptr<ObjCopier> &Result) {
  Result.reset(new ELFCopier<ELFT>(Obj, Out));
  return objcopy_error::success;
}

std::error_code createELFCopier(const object::ObjectFile *Obj,
                                std::unique_ptr<tool_output_file> Out,
                                std::unique_ptr<ObjCopier> &Result) {
  if (const ELF32LEObjectFile *ELFObj = dyn_cast<ELF32LEObjectFile>(Obj))
    return createELFCopier(ELFObj->getELFFile(), Out, Result);

  if (const ELF32BEObjectFile *ELFObj = dyn_cast<ELF32BEObjectFile>(Obj))
    return createELFCopier(ELFObj->getELFFile(), Out, Result);

  if (const ELF64LEObjectFile *ELFObj = dyn_cast<ELF64LEObjectFile>(Obj))
    return createELFCopier(ELFObj->getELFFile(), Out, Result);

  if (const ELF64BEObjectFile *ELFObj = dyn_cast<ELF64BEObjectFile>(Obj))
    return createELFCopier(ELFObj->getELFFile(), Out, Result);

  return objcopy_error:unsupported_obj_file_format;
}

} // namespace llvm

#if 0
template <class ELFT> void Writer<ELFT>::run() {
  createSections();
  copyLocalSymbols();
  
  finalizeSections();
  if (ErrorCount)
    return;

  openFile();
  if (ErrorCount)
    return;

  writeHeader();
  writeSections();

  if (auto EC = Buffer->commit())
    error("failed to write to the output file: " + EC.message());
}
#endif
