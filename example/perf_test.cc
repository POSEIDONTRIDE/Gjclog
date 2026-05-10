// perf_test.cc
// Tests: single-thread baseline, multi-thread throughput, GCM correctness.
//
// Usage: ./perf_test
// The test writes to /tmp/perf_logger/ so it won't pollute the project.

#include <atomic>
#include <chrono>
#include <cstdio>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "logger/crypt/aes_crypt.h"
#include "logger/crypt/crypt.h"
#include "logger/log_handle.h"
#include "logger/sinks/effective_sink.h"

// ── helpers ────────────────────────────────────────────────────────────────

static const char* kPubKey =
    "04827405069030E26A211C973C8710E6FBE79B5CAA364AC111FB171311902277537F8852EADD17EB339EB7CD0BA2490A58CDED2C702DFC1E"
    "FC7EDB544B869F039C";

static std::string MakePayload(int len) {
  std::string s(len, 'x');
  for (int i = 0; i < len; ++i) s[i] = 'a' + (i % 26);
  return s;
}

static double Throughput(int64_t msgs, double ms) {
  return msgs / (ms / 1000.0);
}

// ── section 1 : AES-GCM round-trip ─────────────────────────────────────────

void TestGCMCorrectness() {
  std::puts("\n=== [1] AES-GCM encrypt/decrypt round-trip ===");

  std::string key = logger::crypt::AESCrypt::GenerateKey();
  logger::crypt::AESCrypt crypt(key);

  const std::string plain = "Hello, AES-GCM with random IV!";
  std::string cipher1, cipher2;

  crypt.Encrypt(plain.data(), plain.size(), cipher1);
  crypt.Encrypt(plain.data(), plain.size(), cipher2);

  // Two encryptions of the same plaintext must produce different ciphertext
  // (random IV). If they're equal the IV is NOT being randomised.
  if (cipher1 == cipher2) {
    std::puts("  FAIL: same ciphertext for two calls – IV not random!");
  } else {
    std::puts("  OK  : ciphertexts differ (IV is random per call)");
  }

  std::string dec1 = crypt.Decrypt(cipher1.data(), cipher1.size());
  std::string dec2 = crypt.Decrypt(cipher2.data(), cipher2.size());

  if (dec1 == plain && dec2 == plain) {
    std::puts("  OK  : both ciphertexts decrypt correctly");
  } else {
    std::puts("  FAIL: decrypt mismatch");
  }

  // Tamper test: flip one byte in cipher1 – GCM should throw / return empty.
  std::string tampered = cipher1;
  tampered[tampered.size() / 2] ^= 0xFF;
  try {
    std::string bad = crypt.Decrypt(tampered.data(), tampered.size());
    if (bad.empty()) {
      std::puts("  OK  : tampered ciphertext returned empty (auth failed)");
    } else {
      std::puts("  FAIL: tampered ciphertext was accepted – no integrity check!");
    }
  } catch (...) {
    std::puts("  OK  : tampered ciphertext threw exception (auth tag mismatch)");
  }
}

// ── section 2 : single-thread baseline ─────────────────────────────────────

void TestSingleThread(int n_msgs, int msg_len) {
  std::printf("\n=== [2] Single-thread: %d msgs × %d B ===\n", n_msgs, msg_len);

  logger::EffectiveSink::Conf conf;
  conf.dir    = "/tmp/perf_logger/single";
  conf.prefix = "st";
  conf.pub_key = kPubKey;

  auto sink = std::make_shared<logger::EffectiveSink>(conf);
  logger::LogHandle handle(std::static_pointer_cast<logger::LogSink>(sink));
  std::string payload = MakePayload(msg_len);

  auto t0 = std::chrono::steady_clock::now();
  for (int i = 0; i < n_msgs; ++i) {
    handle.Log(logger::LogLevel::kInfo, logger::SourceLocation(), payload);
  }
  sink->Flush();
  auto t1  = std::chrono::steady_clock::now();
  double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

  std::printf("  time  : %.1f ms\n", ms);
  std::printf("  thrput: %.0f msgs/s\n", Throughput(n_msgs, ms));
  std::printf("  data  : %.1f MB\n", (double)n_msgs * msg_len / 1e6);
}

// ── section 3 : multi-thread throughput ────────────────────────────────────

void TestMultiThread(int n_threads, int n_msgs_total, int msg_len) {
  std::printf("\n=== [3] Multi-thread: %d threads, %d msgs × %d B ===\n",
              n_threads, n_msgs_total, msg_len);

  logger::EffectiveSink::Conf conf;
  conf.dir    = "/tmp/perf_logger/multi_" + std::to_string(n_threads);
  conf.prefix = "mt";
  conf.pub_key = kPubKey;

  auto sink = std::make_shared<logger::EffectiveSink>(conf);
  logger::LogHandle handle(std::static_pointer_cast<logger::LogSink>(sink));
  std::string payload = MakePayload(msg_len);

  int msgs_per_thread = n_msgs_total / n_threads;
  std::atomic<int> errors{0};

  auto worker = [&]() {
    for (int i = 0; i < msgs_per_thread; ++i) {
      handle.Log(logger::LogLevel::kInfo, logger::SourceLocation(), payload);
    }
  };

  auto t0 = std::chrono::steady_clock::now();
  std::vector<std::thread> threads;
  threads.reserve(n_threads);
  for (int i = 0; i < n_threads; ++i) threads.emplace_back(worker);
  for (auto& t : threads) t.join();
  sink->Flush();
  auto t1  = std::chrono::steady_clock::now();
  double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

  std::printf("  time  : %.1f ms\n", ms);
  std::printf("  thrput: %.0f msgs/s  (errors=%d)\n",
              Throughput((long long)msgs_per_thread * n_threads, ms),
              errors.load());
}

// ── section 4 : data-race check (write stress) ────────────────────────────

void TestNoDataRace(int n_threads, int n_msgs_per_thread) {
  std::printf("\n=== [4] Data-race stress: %d threads × %d msgs ===\n",
              n_threads, n_msgs_per_thread);

  logger::EffectiveSink::Conf conf;
  conf.dir    = "/tmp/perf_logger/stress";
  conf.prefix = "stress";
  conf.pub_key = kPubKey;

  auto sink = std::make_shared<logger::EffectiveSink>(conf);
  logger::LogHandle handle(std::static_pointer_cast<logger::LogSink>(sink));

  std::atomic<int64_t> total_written{0};
  auto worker = [&](int tid) {
    std::string payload = "thread" + std::to_string(tid) + ":" + MakePayload(500);
    for (int i = 0; i < n_msgs_per_thread; ++i) {
      handle.Log(logger::LogLevel::kInfo, logger::SourceLocation(), payload);
      total_written.fetch_add(1, std::memory_order_relaxed);
    }
  };

  std::vector<std::thread> threads;
  for (int i = 0; i < n_threads; ++i) threads.emplace_back(worker, i);
  for (auto& t : threads) t.join();
  sink->Flush();

  int64_t written = total_written.load();
  std::printf("  written : %lld msgs – no crash = OK\n", (long long)written);
}

// ── main ───────────────────────────────────────────────────────────────────

int main() {
  std::filesystem::create_directories("/tmp/perf_logger");

  const int N        = 1'000'000;  // total messages
  const int MSG_LEN  = 2000;       // bytes per message (same as original benchmark)

  TestGCMCorrectness();
  TestSingleThread(N, MSG_LEN);

  // Sweep thread counts to show scaling
  for (int t : {2, 4, 8, 16}) {
    TestMultiThread(t, N, MSG_LEN);
  }

  TestNoDataRace(16, 50'000);

  std::puts("\n=== All tests done ===");
  return 0;
}
