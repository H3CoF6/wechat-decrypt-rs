# wx-dump-rs DLL API 文档

`wx-dump-rs` 不仅作为一个独立的命令行工具（CLI），还可以被编译为动态链接库 (DLL/SO) 供外部程序（如 Python, C#, C++ 等）调用。本接口文档介绍了如何使用该 DLL。

## 函数总览

所有函数通过 C-ABI 导出（`extern "C"`）。由于跨语言调用的复杂性，所有的返回值均序列化为 JSON 字符串，便于其他语言解析。

注意：所有通过 DLL 返回的字符串指针（`*mut c_char`），在外部语言读取完毕后，**必须**调用 `free_string` 进行内存释放，否则会导致内存泄漏。

### 1. `get_wechat_state`

**说明**：扫描当前微信状态，自动定位微信数据目录和当前登录账户信息。

- **参数**：无
- **返回**：`*mut c_char` (JSON 格式)
- **JSON 结构**：
  ```json
  {
      "pid": 12345,
      "data_dir": "C:\\Users\\xxx\\Documents\\xwechat_files",
      "wxid": "wxid_xxxxxxxx",
      "nickname": "微信昵称",
      "uids": ["123456789"]
  }
  ```
  *(注：如果发生错误，返回 `{ "error": "错误信息" }`)*

### 2. `get_db_keys`

**说明**：输入微信 PID 和数据库目录，扫描微信内存中的数据库派生密钥。

- **参数**：
  - `pid`: `u32` (微信进程的 PID)
  - `db_dir`: `*const c_char` (包含要扫描的 `.db` 文件的目录路径的 UTF-8 字符串指针)
- **返回**：`*mut c_char` (JSON 格式)
- **JSON 结构**：
  ```json
  {
      "keys": [
          {
              "name": "MicroMsg.db",
              "filepath": "C:\\...\\MicroMsg.db",
              "salt": "abcd1234...",
              "key": "ffff..."
          }
      ]
  }
  ```

### 3. `get_image_keys`

**说明**：自动扫描本机微信配置，无需参数，计算出当前账号可能的所有图片（`.dat`）解密密钥组合（AES key 和 XOR key）。

- **参数**：无
- **返回**：`*mut c_char` (JSON 格式)
- **JSON 结构**：
  ```json
  {
      "keys": [
          {
              "xor_key": 125,
              "aes_key_v2": "abcdef1234567890..."
          }
      ]
  }
  ```

### 4. `batch_decrypt_images`

**说明**：给定密钥、加密的 `.dat` 图片所在目录以及输出目录，进行并发批量解密。

- **参数**：
  - `aes_key_hex`: `*const c_char` (十六进制编码的 AES Key)
  - `xor_key`: `u8` (单字节 XOR Key)
  - `account_dir`: `*const c_char` (要解密的 `.dat` 目录路径)
  - `out_dir`: `*const c_char` (解密后文件的输出目录)
- **返回**：`*mut c_char` (JSON 格式)
- **JSON 结构**：
  ```json
  {
      "total": 100,
      "success": 99
  }
  ```

### 5. `free_string`

**说明**：释放由 DLL 申请并返回给外部环境的字符串内存。

- **参数**：
  - `ptr`: `*mut c_char` (要释放的字符串指针)
- **返回**：无