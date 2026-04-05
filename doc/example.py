import ctypes
import json
import os
import sys

dll_name = ""

if sys.platform == 'win32':
    dll_name = "wx_dump.dll"
else:
    sys.exit(1)

# 如果你在 target/release 目录下编译了项目，请调整相对路径
dll_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "target", "release", dll_name))

if not os.path.exists(dll_path):
    print(f"找不到 DLL: {dll_path}，请先运行 `cargo build --release`")
    sys.exit(1)


wx_dump = ctypes.CDLL(dll_path)


wx_dump.get_wechat_state.restype = ctypes.c_void_p
wx_dump.get_db_keys.restype = ctypes.c_void_p
wx_dump.get_db_keys.argtypes = [ctypes.c_uint32, ctypes.c_char_p]
wx_dump.get_image_keys.restype = ctypes.c_void_p
wx_dump.batch_decrypt_images.restype = ctypes.c_void_p
wx_dump.batch_decrypt_images.argtypes = [ctypes.c_char_p, ctypes.c_uint8, ctypes.c_char_p, ctypes.c_char_p]
wx_dump.free_string.argtypes = [ctypes.c_void_p]

def call_dll_json(func, *args):
    """通用辅助函数：调用 DLL，解析 JSON，并释放返回的 C 字符串"""
    ptr = func(*args)
    if not ptr:
        return None
    
    # 转换 C 指针到 Python 字符串
    json_str = ctypes.cast(ptr, ctypes.c_char_p).value.decode('utf-8')
    
    # 调用 DLL 的 free_string 释放 Rust 内存
    wx_dump.free_string(ptr)
    
    return json.loads(json_str)

def main():
    print("=== 1. 获取微信状态 ===")
    state = call_dll_json(wx_dump.get_wechat_state)
    print(json.dumps(state, indent=2, ensure_ascii=False))
    
    if "error" in state:
        print("获取微信状态失败，可能是微信未登录。")
        return

    pid = state["pid"]
    data_dir = state["data_dir"]
    wxid = state["wxid"]

    ##  注意！！！！  这里的传入路径是错的，需要根据实际情况自行修改    ！！！！！！！ todo
    db_storage_dir = os.path.join(data_dir, wxid, "db_storage")

    print(f"\n=== 2. 获取数据库密钥 (扫描 {db_storage_dir}) ===")
    # 这一步可能会比较慢，因为需要扫描内存
    db_keys = call_dll_json(wx_dump.get_db_keys, pid, db_storage_dir.encode('utf-8'))
    print(json.dumps(db_keys, indent=2, ensure_ascii=False))

    print("\n=== 3. 自动计算可能的图片解密密钥 ===")
    image_keys = call_dll_json(wx_dump.get_image_keys)
    print(json.dumps(image_keys, indent=2, ensure_ascii=False))

    print("\n=== 4. 批量解密测试 ===")
    # 假设我们想解密该账号下所有接收到的媒体图片
    # 将输出存到桌面的 decrypted_images
    media_dir = os.path.join(data_dir, wxid) # 可以传父目录，DLL里面会自动递归找 .dat 文件
    out_dir = os.path.join(os.path.expanduser("~"), "Desktop", "decrypted_images")
    
    keys_list = image_keys.get("keys", [])
    if keys_list:
        first_key = keys_list[0]
        aes_hex = first_key["aes_key_v2"]
        xor_val = first_key["xor_key"]
        
        print(f"正在使用 AES: {aes_hex}, XOR: {xor_val} 进行解密...")
        print(f"源文件夹: {media_dir}")
        print(f"输出文件夹: {out_dir}")
        
        result = call_dll_json(
            wx_dump.batch_decrypt_images,
            aes_hex.encode('utf-8'),
            xor_val,
            media_dir.encode('utf-8'),
            out_dir.encode('utf-8')
        )
        print(json.dumps(result, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
