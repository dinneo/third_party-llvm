//===- Fuchsia/Path.inc - Fuchsia Path Implementation -----------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements the Fuchsia specific implementation of the Path API.
//
//===----------------------------------------------------------------------===//

#include "Fuchsia.h"

#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <paths.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <unistd.h>

using namespace llvm;

namespace llvm {
namespace sys  {
namespace fs {

std::string getMainExecutable(const char *argv0, void *MainAddr) {
  Dl_info DLInfo;
  int err = dladdr(MainAddr, &DLInfo);
  if (err == 0)
    return "";

  char link_path[MAXPATHLEN];
  if (realpath(DLInfo.dli_fname, link_path))
    return link_path;
  return "";
}

TimePoint<> basic_file_status::getLastAccessedTime() const {
  return toTimePoint(fs_st_atime);
}

TimePoint<> basic_file_status::getLastModificationTime() const {
  return toTimePoint(fs_st_mtime);
}

UniqueID file_status::getUniqueID() const {
  return UniqueID(fs_st_dev, fs_st_ino);
}

uint32_t file_status::getLinkCount() const {
  return fs_st_nlinks;
}

ErrorOr<space_info> disk_space(const Twine &Path) {
  struct statfs Fs;
  if (::statfs(Path.str().c_str(), &Fs))
    return std::error_code(errno, std::generic_category());
  space_info SpaceInfo;
  SpaceInfo.capacity = static_cast<uint64_t>(Fs.f_blocks) * Fs.f_bsize;
  SpaceInfo.free = static_cast<uint64_t>(Fs.f_bfree) * Fs.f_bsize;
  SpaceInfo.available = static_cast<uint64_t>(Fs.f_bavail) * Fs.f_bsize;
  return SpaceInfo;
}

std::error_code current_path(SmallVectorImpl<char> &result) {
  result.clear();

  const char *pwd = std::getenv("PWD");
  llvm::sys::fs::file_status PWDStatus, DotStatus;
  if (pwd && llvm::sys::path::is_absolute(pwd) &&
      !llvm::sys::fs::status(pwd, PWDStatus) &&
      !llvm::sys::fs::status(".", DotStatus) &&
      PWDStatus.getUniqueID() == DotStatus.getUniqueID()) {
    result.append(pwd, pwd + strlen(pwd));
    return std::error_code();
  }

  result.reserve(MAXPATHLEN);

  while (true) {
    if (::getcwd(result.data(), result.capacity()) == nullptr) {
      // See if there was a real error.
      if (errno != ENOMEM)
        return std::error_code(errno, std::generic_category());
      // Otherwise there just wasn't enough space.
      result.reserve(result.capacity() * 2);
    } else
      break;
  }

  result.set_size(strlen(result.data()));
  return std::error_code();
}

std::error_code set_current_path(const Twine &path) {
  SmallString<128> path_storage;
  StringRef p = path.toNullTerminatedStringRef(path_storage);

  if (::chdir(p.begin()) == -1)
    return std::error_code(errno, std::generic_category());

  return std::error_code();
}

std::error_code create_directory(const Twine &path, bool IgnoreExisting,
                                 perms Perms) {
  SmallString<128> path_storage;
  StringRef p = path.toNullTerminatedStringRef(path_storage);

  if (::mkdir(p.begin(), Perms) == -1) {
    if (errno != EEXIST || !IgnoreExisting)
      return std::error_code(errno, std::generic_category());
  }

  return std::error_code();
}

std::error_code create_link(const Twine &to, const Twine &from) {
  return std::error_code();
}

std::error_code create_hard_link(const Twine &to, const Twine &from) {
  return std::error_code();
}

std::error_code remove(const Twine &path, bool IgnoreNonExisting) {
  SmallString<128> path_storage;
  StringRef p = path.toNullTerminatedStringRef(path_storage);

  struct stat buf;
  if (lstat(p.begin(), &buf) != 0) {
    if (errno != ENOENT || !IgnoreNonExisting)
      return std::error_code(errno, std::generic_category());
    return std::error_code();
  }

  // Note: this check catches strange situations. In all cases, LLVM should
  // only be involved in the creation and deletion of regular files.  This
  // check ensures that what we're trying to erase is a regular file. It
  // effectively prevents LLVM from erasing things like /dev/null, any block
  // special file, or other things that aren't "regular" files.
  if (!S_ISREG(buf.st_mode) && !S_ISDIR(buf.st_mode) && !S_ISLNK(buf.st_mode))
    return make_error_code(errc::operation_not_permitted);

  if (::unlink(p.begin()) == -1) {
    if (errno != ENOENT || !IgnoreNonExisting)
      return std::error_code(errno, std::generic_category());
  }

  return std::error_code();
}

std::error_code is_local(const Twine &Path, bool &Result) {
  Result = true;
  return std::error_code();
}

std::error_code is_local(int FD, bool &Result) {
  Result = true;
  return std::error_code();
}

std::error_code rename(const Twine &from, const Twine &to) {
  SmallString<128> from_storage;
  SmallString<128> to_storage;
  StringRef f = from.toNullTerminatedStringRef(from_storage);
  StringRef t = to.toNullTerminatedStringRef(to_storage);

  if (::rename(f.begin(), t.begin()) == -1)
    return std::error_code(errno, std::generic_category());

  return std::error_code();
}

std::error_code resize_file(int FD, uint64_t Size) {
  if (::ftruncate(FD, Size) == -1)
    return std::error_code(errno, std::generic_category());
  return std::error_code();
}

static int convertAccessMode(AccessMode Mode) {
  switch (Mode) {
  case AccessMode::Exist:
    return F_OK;
  case AccessMode::Write:
    return W_OK;
  case AccessMode::Execute:
    return R_OK | X_OK; // scripts also need R_OK.
  }
  llvm_unreachable("invalid enum");
}

std::error_code access(const Twine &Path, AccessMode Mode) {
  SmallString<128> PathStorage;
  StringRef P = Path.toNullTerminatedStringRef(PathStorage);

  struct stat buf;
  if (stat(P.begin(), &buf) != 0)
    return errc::permission_denied;

  if (Mode == AccessMode::Execute) {
    // Don't say that directories are executable.
    if (!S_ISREG(buf.st_mode))
      return errc::permission_denied;
  }

  return std::error_code();
}

bool can_execute(const Twine &Path) {
  return !access(Path, AccessMode::Execute);
}

bool equivalent(file_status A, file_status B) {
  assert(status_known(A) && status_known(B));
  return A.fs_st_dev == B.fs_st_dev &&
         A.fs_st_ino == B.fs_st_ino;
}

std::error_code equivalent(const Twine &A, const Twine &B, bool &result) {
  file_status fsA, fsB;
  if (std::error_code ec = status(A, fsA))
    return ec;
  if (std::error_code ec = status(B, fsB))
    return ec;
  result = equivalent(fsA, fsB);
  return std::error_code();
}

static void expandTildeExpr(SmallVectorImpl<char> &Path) {
  // Path does not begin with a tilde expression.
  if (Path.empty() || Path[0] != '~')
    return;

  StringRef PathStr(Path.begin(), Path.size());
  PathStr = PathStr.drop_front();
  StringRef Expr = PathStr.take_until([](char c) { return path::is_separator(c); });

  if (!Expr.empty()) {
    // This is probably a ~username/ expression.  Don't support this on Fuchsia.
    return;
  }

  SmallString<128> HomeDir;
  if (!path::home_directory(HomeDir)) {
    // For some reason we couldn't get the home directory.  Just exit.
    return;
  }
}

static std::error_code fillStatus(int StatRet, const struct stat &Status,
                             file_status &Result) {
  if (StatRet != 0) {
    std::error_code ec(errno, std::generic_category());
    if (ec == errc::no_such_file_or_directory)
      Result = file_status(file_type::file_not_found);
    else
      Result = file_status(file_type::status_error);
    return ec;
  }

  file_type Type = file_type::type_unknown;

  if (S_ISDIR(Status.st_mode))
    Type = file_type::directory_file;
  else if (S_ISREG(Status.st_mode))
    Type = file_type::regular_file;
  else if (S_ISBLK(Status.st_mode))
    Type = file_type::block_file;
  else if (S_ISCHR(Status.st_mode))
    Type = file_type::character_file;
  else if (S_ISFIFO(Status.st_mode))
    Type = file_type::fifo_file;
  else if (S_ISSOCK(Status.st_mode))
    Type = file_type::socket_file;

  perms Perms = static_cast<perms>(Status.st_mode) & all_perms;
  Result = file_status(Type, Perms, Status.st_dev, Status.st_nlink,
                       Status.st_ino, Status.st_atime, Status.st_mtime,
                       Status.st_uid, Status.st_gid, Status.st_size);

  return std::error_code();
}

std::error_code status(const Twine &Path, file_status &Result, bool Follow) {
  SmallString<128> PathStorage;
  StringRef P = Path.toNullTerminatedStringRef(PathStorage);

  struct stat Status;
  int StatRet = ::stat(P.begin(), &Status);
  return fillStatus(StatRet, Status, Result);
}

std::error_code status(int FD, file_status &Result) {
  struct stat Status;
  int StatRet = ::fstat(FD, &Status);
  return fillStatus(StatRet, Status, Result);
}

std::error_code setPermissions(const Twine &Path, perms Permissions) {
  SmallString<128> PathStorage;
  StringRef P = Path.toNullTerminatedStringRef(PathStorage);

  if (::chmod(P.begin(), Permissions))
    return std::error_code(errno, std::generic_category());
  return std::error_code();
}

std::error_code setLastModificationAndAccessTime(int FD, TimePoint<> Time) {
  timespec Times[2];
  Times[0] = Times[1] = sys::toTimeSpec(Time);
  if (::futimens(FD, Times))
    return std::error_code(errno, std::generic_category());
  return std::error_code();
}

std::error_code mapped_file_region::init(int FD, uint64_t Offset,
                                         mapmode Mode) {
  assert(Size != 0);

  int flags = (Mode == readwrite) ? MAP_SHARED : MAP_PRIVATE;
  int prot = (Mode == readonly) ? PROT_READ : (PROT_READ | PROT_WRITE);
  Mapping = ::mmap(nullptr, Size, prot, flags, FD, Offset);
  if (Mapping == MAP_FAILED)
    return std::error_code(errno, std::generic_category());
  return std::error_code();
}

mapped_file_region::mapped_file_region(int fd, mapmode mode, uint64_t length,
                                       uint64_t offset, std::error_code &ec)
    : Size(length), Mapping() {
  // Make sure that the requested size fits within SIZE_T.
  if (length > std::numeric_limits<size_t>::max()) {
    ec = make_error_code(errc::invalid_argument);
    return;
  }

  ec = init(fd, offset, mode);
  if (ec)
    Mapping = nullptr;
}

mapped_file_region::~mapped_file_region() {
  if (Mapping)
    ::munmap(Mapping, Size);
}

uint64_t mapped_file_region::size() const {
  assert(Mapping && "Mapping failed but used anyway!");
  return Size;
}

char *mapped_file_region::data() const {
  assert(Mapping && "Mapping failed but used anyway!");
  return reinterpret_cast<char*>(Mapping);
}

const char *mapped_file_region::const_data() const {
  assert(Mapping && "Mapping failed but used anyway!");
  return reinterpret_cast<const char*>(Mapping);
}

int mapped_file_region::alignment() {
  return Process::getPageSize();
}

std::error_code detail::directory_iterator_construct(detail::DirIterState &it,
                                                     StringRef path,
                                                     bool follow_symlinks){
  SmallString<128> path_null(path);
  DIR *directory = ::opendir(path_null.c_str());
  if (!directory)
    return std::error_code(errno, std::generic_category());

  it.IterationHandle = reinterpret_cast<intptr_t>(directory);
  // Add something for replace_filename to replace.
  path::append(path_null, ".");
  it.CurrentEntry = directory_entry(path_null.str(), follow_symlinks);
  return directory_iterator_increment(it);
}

std::error_code detail::directory_iterator_destruct(detail::DirIterState &it) {
  if (it.IterationHandle)
    ::closedir(reinterpret_cast<DIR *>(it.IterationHandle));
  it.IterationHandle = 0;
  it.CurrentEntry = directory_entry();
  return std::error_code();
}

std::error_code detail::directory_iterator_increment(detail::DirIterState &it) {
  errno = 0;
  dirent *cur_dir = ::readdir(reinterpret_cast<DIR *>(it.IterationHandle));
  if (cur_dir == nullptr && errno != 0) {
    return std::error_code(errno, std::generic_category());
  } else if (cur_dir != nullptr) {
    StringRef name(cur_dir->d_name, strlen((cur_dir)->d_name));
    if ((name.size() == 1 && name[0] == '.') ||
        (name.size() == 2 && name[0] == '.' && name[1] == '.'))
      return directory_iterator_increment(it);
    it.CurrentEntry.replace_filename(name);
  } else
    return directory_iterator_destruct(it);

  return std::error_code();
}

ErrorOr<basic_file_status> directory_entry::status() const {
  file_status s;
  if (auto EC = fs::status(Path, s, FollowSymlinks))
    return EC;
  return s;
}

std::error_code openFileForRead(const Twine &Name, int &ResultFD,
                                SmallVectorImpl<char> *RealPath) {
  SmallString<128> Storage;
  StringRef P = Name.toNullTerminatedStringRef(Storage);
  while ((ResultFD = ::open(P.begin(), O_RDONLY)) < 0) {
    if (errno != EINTR)
      return std::error_code(errno, std::generic_category());
  }
  if (!RealPath)
    return std::error_code();
  RealPath->clear();
  return std::error_code();
}

std::error_code openFileForWrite(const Twine &Name, int &ResultFD,
                            sys::fs::OpenFlags Flags, unsigned Mode) {
  // Verify that we don't have both "append" and "excl".
  assert((!(Flags & sys::fs::F_Excl) || !(Flags & sys::fs::F_Append)) &&
         "Cannot specify both 'excl' and 'append' file creation flags!");

  int OpenFlags = O_CREAT;

  if (Flags & F_RW)
    OpenFlags |= O_RDWR;
  else
    OpenFlags |= O_WRONLY;

  if (Flags & F_Append)
    OpenFlags |= O_APPEND;
  else
    OpenFlags |= O_TRUNC;

  if (Flags & F_Excl)
    OpenFlags |= O_EXCL;

  SmallString<128> Storage;
  StringRef P = Name.toNullTerminatedStringRef(Storage);
  while ((ResultFD = ::open(P.begin(), OpenFlags, Mode)) < 0) {
    if (errno != EINTR)
      return std::error_code(errno, std::generic_category());
  }
  return std::error_code();
}

template <typename T>
static std::error_code remove_directories_impl(const T &Entry,
                                               bool IgnoreErrors) {
  std::error_code EC;
  directory_iterator Begin(Entry, EC, false);
  directory_iterator End;
  while (Begin != End) {
    auto &Item = *Begin;
    ErrorOr<basic_file_status> st = Item.status();
    if (!st && !IgnoreErrors)
      return st.getError();

    if (is_directory(*st)) {
      EC = remove_directories_impl(Item, IgnoreErrors);
      if (EC && !IgnoreErrors)
        return EC;
    }

    EC = fs::remove(Item.path(), true);
    if (EC && !IgnoreErrors)
      return EC;

    Begin.increment(EC);
    if (EC && !IgnoreErrors)
      return EC;
  }
  return std::error_code();
}

std::error_code remove_directories(const Twine &path, bool IgnoreErrors) {
  auto EC = remove_directories_impl(path, IgnoreErrors);
  if (EC && !IgnoreErrors)
    return EC;
  EC = fs::remove(path, true);
  if (EC && !IgnoreErrors)
    return EC;
  return std::error_code();
}

std::error_code real_path(const Twine &path, SmallVectorImpl<char> &dest,
                          bool expand_tilde) {
  dest.clear();
  if (path.isTriviallyEmpty())
    return std::error_code();

  if (expand_tilde) {
    SmallString<128> Storage;
    path.toVector(Storage);
    expandTildeExpr(Storage);
    return real_path(Storage, dest, false);
  }

  int fd;
  std::error_code EC = openFileForRead(path, fd, &dest);

  if (EC)
    return EC;
  ::close(fd);
  return std::error_code();
}

} // end namespace fs

namespace path {

bool home_directory(SmallVectorImpl<char> &result) {
  if (char *RequestedDir = std::getenv("HOME")) {
    result.clear();
    result.append(RequestedDir, RequestedDir + strlen(RequestedDir));
    return true;
  }

  return false;
}

static bool getUserCacheDir(SmallVectorImpl<char> &Result) {
  // Use "$HOME/.cache" if $HOME is available
  if (home_directory(Result)) {
    append(Result, ".cache");
    return true;
  }

  return false;
}

static const char *getEnvTempDir() {
  const char *EnvironmentVariables[] = {"TMPDIR", "TMP", "TEMP", "TEMPDIR"};
  for (const char *Env : EnvironmentVariables) {
    if (const char *Dir = std::getenv(Env))
      return Dir;
  }

  return nullptr;
}

static const char *getDefaultTempDir() {
  return _PATH_TMP;
}

void system_temp_directory(bool ErasedOnReboot, SmallVectorImpl<char> &Result) {
  (void)ErasedOnReboot;
  Result.clear();

  if (const char *RequestedDir = getEnvTempDir()) {
    Result.append(RequestedDir, RequestedDir + strlen(RequestedDir));
    return;
  }

  const char *RequestedDir = getDefaultTempDir();
  Result.append(RequestedDir, RequestedDir + strlen(RequestedDir));
}

} // end namespace path

} // end namespace sys
} // end namespace llvm
