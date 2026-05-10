#pragma once

#include <atomic>
#include <chrono>
#include <filesystem>
#include <mutex>

#include "compress/compress.h"
#include "context/context.h"
#include "crypt/crypt.h"
#include "mmap/mmap_aux.h"
#include "sinks/sink.h"
#include "space.h"

namespace logger {

namespace detail {
struct ChunkHeader {
  static constexpr uint64_t kMagic = 0xdeadbeefdada1100;
  uint64_t magic;
  uint64_t size;
  char pub_key[128];

  ChunkHeader() : magic(kMagic), size(0) {}
};

struct ItemHeader {
  static constexpr uint32_t kMagic = 0xbe5fba11;
  uint32_t magic;
  uint32_t size;

  ItemHeader() : magic(kMagic), size(0) {}
};

}  // namespace detail

class EffectiveSink final : public LogSink {
 public:
  struct Conf {
    std::filesystem::path dir;         // 文件目录
    std::string prefix;                // 文件名前缀，文件名命名格式：{prefix}_{datetime}.log
    std::string pub_key;               // 公钥
    std::chrono::minutes interval{5};  // 淘汰间隔
    megabytes single_size{4};          // 单个文件大小
    megabytes total_size{100};         // 总共文件大小
  };

  explicit EffectiveSink(Conf conf);

  ~EffectiveSink() override = default;

  void Log(const LogMsg& msg) override;

  void SetFormatter(std::unique_ptr<Formatter> formatter) override;

  void Flush() override;

 private:
  void SwapCache_();

  bool NeedCacheToFile_();

  void WriteToCache_(const void* data, uint32_t size);

  void PrepareToFile_();

  void CacheToFile_();

  std::filesystem::path GetFilePath_();

  void ElimateFiles_();

 private:
  Conf conf_;
  std::mutex mutex_;
  std::unique_ptr<Formatter> formatter_;
  ctx::TaskRunnerTag task_runner_;
  std::unique_ptr<crypt::Crypt> crypt_;
  std::unique_ptr<MMapAux> master_cache_;
  std::unique_ptr<MMapAux> slave_cache_;
  std::filesystem::path log_file_path_;
  std::string client_pub_key_;
  std::atomic<bool> is_slave_free_{true};
  // Sidecar key files: persist which client pub key was used to encrypt data
  // currently sitting in each mmap cache. Enables correct ChunkHeader on crash recovery.
  std::filesystem::path master_key_path_;
  std::filesystem::path slave_key_path_;
  std::string slave_cache_pub_key_;  // pub key for data currently in slave_cache_
};

}  // namespace logger
