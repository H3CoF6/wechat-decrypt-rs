# WeChat-Decrypt-rs

工具**完全由 Rust 编写**，通过**扫描进程内存与本地缓存**实现解密，

轻量、极速、安全。

> *注：本工具目前仅支持windows x86_64用户测试体验，未来可能会适配更多平台*

## 核心优势

| **特性**           | **说明**                                                     |
| ------------------ | ------------------------------------------------------------ |
| **极速 (Faster)**  | 告别 Python 或 JavaScript (Node.js) 庞大的解释器与运行时开销。Rust 带来的底层性能优势结合无畏并发（Rayon 多线程），将扫盘、特征匹配与 AES 解密的速度推向极致。 |
| **轻量 (Lighter)** | 无需配置 Python 环境，无需 `npm install` 等繁琐的依赖安装。纯静态编译，单可执行文件，开箱即用。 |
| **安全 (Safer)**   | **无 DLL 注入，无 Inline Hook。** 完全不修改微信进程的任何函数或内存，仅通过系统 API 进行纯外部的内存安全读取，彻底规避了传统 Hook 方案带来的破坏性与高封号风险。 |

## 使用方式

> [!note]
>
> **运行本工具前，请务必确保微信已经在当前电脑上成功登录**
>
> **否则程序无法从内存中获取有效的解密密钥。**

> **注意：该工具会自动检测当前登录账号**，且仅支持解密当前登录账号的数据！！

本程序为无额外依赖的单体可执行文件：

```powershell
.\wx-dump-rs.exe
```

程序启动后，会自动完成环境探测、PID 锁定、数据目录定位以及高并发解密。

解密后的数据库文件与多媒体资源将按类目输出到当前运行目录下的 `output/<wxid>/` 文件夹中。

## 获取与构建

### 1. 下载预编译版本
您可以前往项目的 [Releases 页面](https://github.com/H3CoF6/wechat-decrypt-rs/releases) 下载由 GitHub Actions 自动构建的最新版本。压缩包内包含了：
- `wx-dump-rs.exe`：独立的命令行工具，双击即可使用。
- `wx_dump.dll`：动态链接库，供外部程序调用。

### 2. 源码编译构建
确保您已安装最新的 [Rust 工具链 (rustup)](https://rustup.rs/)，然后执行：

```powershell
# 1. 克隆代码仓库
git clone https://github.com/H3CoF6/wechat-decrypt-rs.git
cd wechat-decrypt-rs

# 2. 编译 Release 版本（同时生成 CLI 和 DLL）
cargo build --release
```

编译完成后，您可以在 `target/release/` 目录下找到：
- CLI 工具: `target/release/wx-dump-rs.exe`
- 动态链接库: `target/release/wx_dump.dll`

## 作为 DLL 外部调用 (供第三方开发)

本工具不仅仅是一个 CLI，**还可以作为 DLL 被其他语言（如 Python, C#, C++）加载和调用**，从而提供了一套完整的微信数据导出“一条龙”底层 API：

- `get_wechat_state()`: 自动扫描微信 PID，读取本地登录账户的 `wxid` 及配置目录。
- `get_db_keys(...)`: 扫描内存获取所有数据库的解密盐值 (salt) 和密钥 (key)。
- `get_image_keys()`: 无需任何输入参数，自动计算当前登录账号可能的所有图片 `.dat` 文件解密组合 (AES + XOR)。
- `batch_decrypt_images(...)`: 传入提取出的密钥，极速并发解密图片目录。

以上接口统一采用 JSON 字符串传递参数和返回值，适配门槛极低。
详细的 API 接口说明和 Python 调用示例，请参阅：
- [DLL API 文档](./doc/api.md)
- [Python 调用示例](./doc/example.py)