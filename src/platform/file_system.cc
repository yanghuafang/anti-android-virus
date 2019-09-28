#include "platform/file_system.h"

#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>

namespace aav {

FileSystem::FileSystem() = default;

FileSystem::~FileSystem() = default;

int FileSystem::CreateFile(const char* path) {
  if (nullptr == path) {
    return -1;
  }

  std::FILE* file = std::fopen(path, "r+");
  if (nullptr == file) {
    return -1;
  }
  std::fclose(file);
  file = nullptr;
  return 0;
}

int FileSystem::RemoveFile(const char* path) { return unlink(path); }

int FileSystem::CopyFile(const char* /*src*/, const char* /*dst*/) { return 0; }

int FileSystem::MoveFile(const char* src, const char* dst) {
  return std::rename(src, dst);
}

bool FileSystem::FileExists(const char* path) {
  if (nullptr == path) {
    return false;
  }

  struct stat st;
  if (0 != stat(path, &st)) {
    return false;
  }
  if (S_IFREG & st.st_mode) {
    return true;
  }
  return false;
}

int FileSystem::GetFileSize(const char* path, int64_t* file_size) {
  struct stat st;
  if (0 != lstat(path, &st)) {
    return -1;
  }
  if (!(S_IFREG & st.st_mode)) {
    return -1;
  }
  *file_size = st.st_size;
  return 0;
}

int FileSystem::CreateTempFile(char* /*path_buf*/, int /*path_buf_size*/) {
  return 0;
}

int FileSystem::MakeDir(const char* path) {
  return mkdir(path, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
}

int FileSystem::RemoveDir(const char* path) { return rmdir(path); }

bool FileSystem::DirExists(const char* path) {
  if (nullptr == path) {
    return false;
  }

  struct stat st;
  if (0 != stat(path, &st)) {
    return false;
  }
  if (S_IFDIR & st.st_mode) {
    return true;
  }
  return false;
}

int FileSystem::GetCurrentDir(char* path_buf, int path_buf_size) {
  if (nullptr == getcwd(path_buf, path_buf_size)) {
    return -1;
  }
  return 0;
}

int FileSystem::SetCurrentDir(const char* path) { return chdir(path); }

}  // namespace aav
