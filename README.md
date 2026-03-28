# Effective Logger

一个基于 mmap + 双缓冲 + Strand 机制的高性能 C++ 日志系统。

## 特性

- mmap 内存映射写入，避免系统调用开销
- 双缓冲 + Strand 机制，业务线程零阻塞
- AES 加密存储，protobuf 序列化
- zstd/zlib 压缩支持
- 日志文件自动滚动与大小限制

## 性能

与 spdlog（异步模式）对比测试（100万条，每条2000字节）：

| 场景 | Spdlog (Async) | Effective Logger | 结论 |
|------|---------------|-----------------|------|
| 单线程 / 64B | 0.82 µs | 3.03 µs | 小包 spdlog 略快 |
| 单线程 / 4KB | 14.14 µs | 3.52 µs | Effective 快 4 倍 |
| 4线程 / 64B | 5.23 µs | 4.16 µs | Effective 快 20% |
| 4线程 / 4KB | 20.38 µs | 5.28 µs | Effective 快 3.8 倍 |

大包/高并发场景下，将延迟从 20µs 压降至 5µs，业务线程阻塞时间减少 75%。

## 依赖

- zstd 1.5.6
- zlib 1.2.13
- protobuf 21.8
- cryptopp 8.9.0
- fmt 11.0.2

## 构建
```bash
python3 script/build_linux.py
```
