#include <chrono>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "logger/compress/zlib_compress.h"
#include "logger/compress/zstd_compress.h"

// 模拟真实日志条目：结构高度相似，前缀大量重复
static std::string MakeLogEntry(int index) {
  std::ostringstream oss;
  oss << "[2026-04-22 10:23:45.123][INFO][thread-" << (index % 16)
      << "][effective_sink.cc:88] WriteToCache_ called, index=" << index
      << ", size=2048, master_ratio=0.72, msg=this is a typical log message with some payload data"
      << std::string(50, 'x');  // 凑到约 200 字节
  return oss.str();
}

struct Result {
  double compress_ms;
  double decompress_ms;
  size_t original_size;
  size_t compressed_size;
  double ratio;  // 压缩后/压缩前，越小越好
};

Result BenchmarkZstd(const std::vector<std::string>& entries, bool streaming) {
  logger::compress::ZstdCompress comp;
  comp.ResetStream();

  size_t total_original = 0;
  size_t total_compressed = 0;

  auto t0 = std::chrono::high_resolution_clock::now();

  std::vector<std::string> compressed_chunks;
  for (const auto& entry : entries) {
    if (!streaming) comp.ResetStream();  // 非流式：每条独立重置

    size_t bound = comp.CompressedBound(entry.size());
    std::string buf(bound, '\0');
    size_t n = comp.Compress(entry.data(), entry.size(), buf.data(), buf.size());
    buf.resize(n);
    total_original += entry.size();
    total_compressed += n;
    compressed_chunks.push_back(std::move(buf));
  }

  auto t1 = std::chrono::high_resolution_clock::now();

  // 解压验证
  logger::compress::ZstdCompress decomp;
  size_t ok = 0;
  for (size_t i = 0; i < compressed_chunks.size(); ++i) {
    auto out = decomp.Decompress(compressed_chunks[i].data(), compressed_chunks[i].size());
    if (out == entries[i]) ++ok;
  }

  auto t2 = std::chrono::high_resolution_clock::now();

  Result r;
  r.compress_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
  r.decompress_ms = std::chrono::duration<double, std::milli>(t2 - t1).count();
  r.original_size = total_original;
  r.compressed_size = total_compressed;
  r.ratio = (double)total_compressed / total_original;

  if (ok != entries.size()) {
    std::cerr << "[WARN] Zstd decompress mismatch: " << ok << "/" << entries.size() << "\n";
  }
  return r;
}

Result BenchmarkZlib(const std::vector<std::string>& entries, bool streaming) {
  logger::compress::ZlibCompress comp;
  comp.ResetStream();

  size_t total_original = 0;
  size_t total_compressed = 0;

  auto t0 = std::chrono::high_resolution_clock::now();

  std::vector<std::string> compressed_chunks;
  for (const auto& entry : entries) {
    if (!streaming) comp.ResetStream();

    size_t bound = comp.CompressedBound(entry.size());
    std::string buf(bound, '\0');
    size_t n = comp.Compress(entry.data(), entry.size(), buf.data(), buf.size());
    buf.resize(n);
    total_original += entry.size();
    total_compressed += n;
    compressed_chunks.push_back(std::move(buf));
  }

  auto t1 = std::chrono::high_resolution_clock::now();

  logger::compress::ZlibCompress decomp;
  decomp.ResetStream();
  size_t ok = 0;
  for (size_t i = 0; i < compressed_chunks.size(); ++i) {
    auto out = decomp.Decompress(compressed_chunks[i].data(), compressed_chunks[i].size());
    if (out == entries[i]) ++ok;
  }

  auto t2 = std::chrono::high_resolution_clock::now();

  Result r;
  r.compress_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
  r.decompress_ms = std::chrono::duration<double, std::milli>(t2 - t1).count();
  r.original_size = total_original;
  r.compressed_size = total_compressed;
  r.ratio = (double)total_compressed / total_original;

  if (ok != entries.size()) {
    std::cerr << "[WARN] Zlib decompress mismatch: " << ok << "/" << entries.size() << "\n";
  }
  return r;
}

static void PrintResult(const char* label, const Result& r, int count) {
  double throughput_mb = (r.original_size / 1024.0 / 1024.0) / (r.compress_ms / 1000.0);
  double entries_per_sec = count / (r.compress_ms / 1000.0);
  std::cout << std::left << std::setw(30) << label
            << "  compress=" << std::fixed << std::setprecision(1) << r.compress_ms << "ms"
            << "  decompress=" << r.decompress_ms << "ms"
            << "  ratio=" << std::setprecision(3) << r.ratio
            << "  throughput=" << std::setprecision(1) << throughput_mb << "MB/s"
            << "  (" << (int)(entries_per_sec / 1000) << "k entries/s)"
            << "\n";
}

int main() {
  const int N = 10000;

  std::cout << "生成 " << N << " 条模拟日志...\n";
  std::vector<std::string> entries;
  entries.reserve(N);
  for (int i = 0; i < N; ++i) {
    entries.push_back(MakeLogEntry(i));
  }
  size_t entry_bytes = entries[0].size();
  std::cout << "每条日志约 " << entry_bytes << " 字节，总计 "
            << (N * entry_bytes / 1024) << " KB\n\n";

  std::cout << std::string(90, '-') << "\n";
  std::cout << "场景1：流式压缩（相邻条目共享上下文，模拟真实场景）\n";
  std::cout << std::string(90, '-') << "\n";
  PrintResult("Zstd 流式", BenchmarkZstd(entries, true), N);
  PrintResult("Zlib 流式", BenchmarkZlib(entries, true), N);

  std::cout << "\n";
  std::cout << std::string(90, '-') << "\n";
  std::cout << "场景2：逐条独立压缩（每条 ResetStream，无上下文共享）\n";
  std::cout << std::string(90, '-') << "\n";
  PrintResult("Zstd 独立", BenchmarkZstd(entries, false), N);
  PrintResult("Zlib 独立", BenchmarkZlib(entries, false), N);

  std::cout << "\n说明：ratio = 压缩后大小/原始大小，越小压缩效果越好\n";
  return 0;
}
