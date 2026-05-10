#include "sinks/effective_sink.h"

#include <fstream>

#include "compress/zstd_compress.h"
#include "crypt/aes_crypt.h"
#include "defer.h"
#include "formatter/effective_formatter.h"
#include "internal_log.h"
#include "utils/file_util.h"
#include "utils/sys_util.h"
#include "utils/timer_count.h"

namespace logger {

// --- Key-file helpers (sidecar files that persist which client pub key
//     was used to encrypt data currently in each mmap cache) ---

static void SaveCachePubKey(const std::filesystem::path& path, const std::string& key) {
  std::ofstream ofs(path, std::ios::binary | std::ios::trunc);
  ofs.write(key.data(), static_cast<std::streamsize>(key.size()));
}

static std::string LoadCachePubKey(const std::filesystem::path& path) {
  std::ifstream ifs(path, std::ios::binary);
  if (!ifs) return {};
  return {(std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>()};
}

static void ClearCachePubKey(const std::filesystem::path& path) {
  std::error_code ec;
  std::filesystem::remove(path, ec);
}

// ---------------------------------------------------------------

EffectiveSink::EffectiveSink(Conf conf) : conf_(std::move(conf)) {
  LOG_INFO("EffectiveSink: dir={}, prefix={}, pub_key={}, interval={}, single_size={}, total_size={}",
           conf_.dir.string(), conf_.prefix, conf_.pub_key, conf_.interval.count(), conf_.single_size.count(),
           conf_.total_size.count());
  if (!std::filesystem::exists(conf_.dir)) {
    std::filesystem::create_directories(conf_.dir);
  }
  task_runner_ = NEW_TASK_RUNNER(10086);  // 10086 是文件任务运行器的标识
  formatter_ = std::make_unique<EffectiveFormatter>();

  master_key_path_ = conf_.dir / "master_cache.key";
  slave_key_path_ = conf_.dir / "slave_cache.key";

  // Create mmap caches first so we can inspect them before generating a new key pair.
  master_cache_ = std::make_unique<MMapAux>(conf_.dir / "master_cache");
  slave_cache_ = std::make_unique<MMapAux>(conf_.dir / "slave_cache");
  if (!master_cache_ || !slave_cache_) {
    throw std::runtime_error("EffectiveSink::EffectiveSink: create mmap failed");
  }

  // Load the pub keys that were used to encrypt any residual cache data.
  // These must be read BEFORE we generate a new ephemeral key pair.
  std::string recovery_master_key;
  std::string recovery_slave_key;
  if (!master_cache_->Empty()) {
    recovery_master_key = LoadCachePubKey(master_key_path_);
  }
  if (!slave_cache_->Empty()) {
    recovery_slave_key = LoadCachePubKey(slave_key_path_);
  }

  // Generate a fresh ECDH key pair for this session.
  auto ecdh_key = crypt::GenECDHKey();
  auto client_pri = std::get<0>(ecdh_key);
  client_pub_key_ = std::get<1>(ecdh_key);
  LOG_INFO("EffectiveSink: client pub size {}", client_pub_key_.size());
  std::string svr_pub_key_bin = crypt::HexKeyToBinary(conf_.pub_key);
  std::string shared_secret = crypt::GenECDHSharedSecret(client_pri, svr_pub_key_bin);
  crypt_ = std::make_unique<crypt::AESCrypt>(shared_secret);

  // Crash recovery: process slave first.
  // Use the key that was active when this data was written, not the new one.
  if (!slave_cache_->Empty()) {
    slave_cache_pub_key_ = recovery_slave_key.empty() ? client_pub_key_ : recovery_slave_key;
    is_slave_free_.store(false);
    PrepareToFile_();
    WAIT_TASK_IDLE(task_runner_);
  }

  // Crash recovery: move residual master data to slave and flush.
  if (!master_cache_->Empty()) {
    bool expected = true;
    if (is_slave_free_.compare_exchange_strong(expected, false)) {
      SwapCache_();
      // SwapCache_ sets slave_cache_pub_key_ = client_pub_key_ (for normal writes).
      // Override with the old key because this data predates the current session.
      slave_cache_pub_key_ = recovery_master_key.empty() ? client_pub_key_ : recovery_master_key;
      SaveCachePubKey(slave_key_path_, slave_cache_pub_key_);
    }
    PrepareToFile_();
  }

  // Persist the new session key so it can be retrieved on the next crash recovery.
  SaveCachePubKey(master_key_path_, client_pub_key_);

  POST_REPEATED_TASK(task_runner_, [this]() { ElimateFiles_(); }, conf_.interval, -1);
}

void EffectiveSink::Log(const LogMsg& msg) {
  // 格式化缓冲区：已是 thread_local，在锁外使用是安全的
  static thread_local MemoryBuf buf;
  formatter_->Format(msg, &buf);

  // 每线程独立的压缩上下文：每个线程持有自己的 ZSTD_CCtx，
  // 使压缩可以并行执行。虽然牺牲了跨线程上下文共享，
  // 但线程内的流式压缩仍能捕捉块内重复数据（实测压缩率约 80%）。
  thread_local compress::ZstdCompress tl_compress;

  // 在新块开始时重置流（master 刚被清空）。
  // 在锁外检查；最坏情况两个线程同时重置——
  // 这是无害的，因为重置操作是幂等的。
  if (master_cache_->Empty()) {
    tl_compress.ResetStream();
  }

  // 在锁外压缩——每个线程使用自己的上下文和缓冲区。
  static thread_local std::string tl_compressed_buf;
  tl_compressed_buf.resize(tl_compress.CompressedBound(buf.size()));
  size_t compressed_size =
      tl_compress.Compress(buf.data(), buf.size(), tl_compressed_buf.data(), tl_compressed_buf.size());
  if (compressed_size == 0) {
    LOG_ERROR("EffectiveSink::Log: compress failed");
    return;
  }

  // 在锁外加密——crypt_ 的密钥在构造后为只读；
  // 所有 CryptoPP GCM 对象均为每次 Encrypt 调用的局部变量；
  // IV 每次调用随机生成，因此没有共享的可变状态。
  static thread_local std::string tl_encrypted_buf;
  tl_encrypted_buf.clear();
  crypt_->Encrypt(tl_compressed_buf.data(), compressed_size, tl_encrypted_buf);
  if (tl_encrypted_buf.empty()) {
    LOG_ERROR("EffectiveSink::Log: encrypt failed");
    return;
  }

  // 只有 mmap 写入需要加锁——临界区现在是 O(memcpy)。
  {
    std::lock_guard<std::mutex> lock(mutex_);
    WriteToCache_(tl_encrypted_buf.data(), tl_encrypted_buf.size());
  }

  if (NeedCacheToFile_()) {
    bool expected = true;
    if (is_slave_free_.compare_exchange_strong(expected, false)) {
      SwapCache_();
    }
    PrepareToFile_();
  }
}

void EffectiveSink::SetFormatter(std::unique_ptr<Formatter> formatter) {}

void EffectiveSink::Flush() {
  TIMER_COUNT("Flush");
  // 第一轮：将 slave 中残留的旧数据异步写入文件，然后阻塞等待写完
  PrepareToFile_();
  WAIT_TASK_IDLE(task_runner_);

  // 第二轮：slave 已空闲，将 master 的数据 swap 到 slave，再异步写入文件并等待
  bool expected = true;
  if (is_slave_free_.compare_exchange_strong(expected, false)) {
    SwapCache_();
  }
  PrepareToFile_();
  // 等待第二轮写完，Flush 结束后两个缓冲区均已清空，所有日志确保落盘
  WAIT_TASK_IDLE(task_runner_);
}

void EffectiveSink::SwapCache_() {
  std::lock_guard<std::mutex> lock(mutex_);
  std::swap(master_cache_, slave_cache_);
  // Record which pub key belongs to the data now in slave.
  // Master always holds data from the current session (client_pub_key_).
  slave_cache_pub_key_ = client_pub_key_;
  SaveCachePubKey(slave_key_path_, slave_cache_pub_key_);
}

bool EffectiveSink::NeedCacheToFile_() {
  return master_cache_->GetRatio() > 0.8;
}

void EffectiveSink::WriteToCache_(const void* data, uint32_t size) {
  detail::ItemHeader item_header;
  item_header.size = size;
  master_cache_->Push(&item_header, sizeof(item_header));
  master_cache_->Push(data, size);
}

void EffectiveSink::PrepareToFile_() {
  POST_TASK(task_runner_, [this]() { CacheToFile_(); });
}

void EffectiveSink::CacheToFile_() {
  TIMER_COUNT("CacheToFile_");
  if (is_slave_free_.load()) {
    return;
  }

  if (slave_cache_->Empty()) {
    is_slave_free_.store(true);
    return;
  }

  {
    auto file_path = GetFilePath_();
    detail::ChunkHeader chunk_header;
    chunk_header.size = slave_cache_->Size();
    // Use the key that was active when this chunk was encrypted.
    // On normal writes slave_cache_pub_key_ == client_pub_key_; on crash
    // recovery it holds the key from the crashed session.
    const std::string& pub_key_to_write =
        slave_cache_pub_key_.empty() ? client_pub_key_ : slave_cache_pub_key_;
    memcpy(chunk_header.pub_key, pub_key_to_write.data(), pub_key_to_write.size());
    // 以追加模式将头部和 slave 数据写入文件
    std::ofstream ofs(file_path, std::ios::binary | std::ios::app);
    ofs.write(reinterpret_cast<char*>(&chunk_header), sizeof(chunk_header));
    ofs.write(reinterpret_cast<char*>(slave_cache_->Data()), chunk_header.size);
    ofs.close();
  }

  slave_cache_->Clear();
  slave_cache_pub_key_.clear();
  ClearCachePubKey(slave_key_path_);
  is_slave_free_.store(true);
}

std::filesystem::path EffectiveSink::GetFilePath_() {
  // 文件命名规则：{前缀}_{日期时间}.log 或 {前缀}_{日期时间}_{序号}.log
  auto GetDateTimePath = [this]() -> std::filesystem::path {
    std::time_t now = std::time(nullptr);
    std::tm tm;
    LocalTime(&tm, &now);
    char time_buf[32] = {0};
    std::strftime(time_buf, sizeof(time_buf), "%Y%m%d%H%M%S", &tm);
    return (conf_.dir / (conf_.prefix + "_" + time_buf));
  };

  if (log_file_path_.empty()) {
    log_file_path_ = GetDateTimePath().string() + ".log";
  } else {
    auto file_size = fs::GetFileSize(log_file_path_);
    bytes single_bytes = space_cast<bytes>(conf_.single_size);
    if (file_size > single_bytes.count()) {
      auto date_time_path = GetDateTimePath();
      auto file_path = date_time_path.string() + ".log";
      if (std::filesystem::exists(file_path)) {
        // 统计目录中同一时间戳的文件数量，序号加一
        int index = 0;
        for (auto& p : std::filesystem::directory_iterator(conf_.dir)) {
          if (p.path().filename().string().find(date_time_path.string()) != std::string::npos) {
            ++index;
          }
        }
        log_file_path_ = date_time_path.string() + "_" + std::to_string(index) + ".log";
      } else {
        log_file_path_ = file_path;
      }
    }
  }
  LOG_INFO("EffectiveSink::GetFilePath_: log_file_path={}", log_file_path_.string());
  return log_file_path_;
}

void EffectiveSink::ElimateFiles_() {
  LOG_INFO("EffectiveSink::ElimateFiles_: start");
  std::vector<std::filesystem::path> files;
  for (auto& p : std::filesystem::directory_iterator(conf_.dir)) {
    if (p.path().extension() == ".log") {
      files.push_back(p.path());
    }
  }

  std::sort(files.begin(), files.end(), [](const std::filesystem::path& lhs, const std::filesystem::path& rhs) {
    return std::filesystem::last_write_time(lhs) > std::filesystem::last_write_time(rhs);
  });

  size_t total_bytes = space_cast<bytes>(conf_.total_size).count();
  size_t used_bytes = 0;
  for (auto& file : files) {
    used_bytes += fs::GetFileSize(file);
    if (used_bytes > total_bytes) {
      LOG_INFO("EffectiveSink::ElimateFiles_: remove file={}", file.string());
      std::filesystem::remove(file);
    }
  }
}

}  // namespace logger
