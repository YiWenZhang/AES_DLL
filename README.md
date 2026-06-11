# AES_DLL — AES-256 加密动态链接库

跨语言可调用的 AES-256-CBC 加密 DLL，支持文件和字符串加解密，基于机器特征（MAC 地址）派生密钥。

## 快速开始

### Windows (MSVC)

```bash
# 在 Visual Studio Developer Command Prompt 中：
msbuild AES_DLL.vcxproj -p:Configuration=Release -p:Platform=x64
```

产物在 `x64/Release/AES_DLL.dll` 和 `AES_DLL.lib`。

### 跨平台 (CMake)

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build .
```

## API 接口

所有函数均使用 `__stdcall` 调用约定，`extern "C"` 导出，可从 C / C++ / C# / Python 等语言直接调用。

| 函数 | 说明 |
|------|------|
| `GetMacAddress()` | 获取本机 MAC 地址（十六进制大写字符串，无分隔符） |
| `GenerateKeyFromMachine(key[32])` | 从 MAC 地址派生 32 字节 AES-256 密钥 |
| `AES_EncryptFile(in, out, key[32])` | 加密文件，输出格式：`[16字节IV][密文]` |
| `AES_DecryptFile(in, out, key[32])` | 解密文件，还原明文 |
| `EncryptString(text, key[32])` | 加密字符串，返回十六进制密文 |
| `DecryptString(hex, key[32])` | 解密十六进制密文，还原明文字符串 |
| `FreeString(str)` | 释放 DLL 分配的字符串内存 |

## 使用示例

### C/C++ 隐式链接

```c
#include "AES_DLL.h"
#pragma comment(lib, "AES_DLL.lib")

int main() {
    uint8_t key[32];
    GenerateKeyFromMachine(key);
    AES_EncryptFile(L"plain.txt", L"encrypted.bin", key);
    AES_DecryptFile(L"encrypted.bin", L"decrypted.txt", key);
    return 0;
}
```

### C# P/Invoke

```csharp
[DllImport("AES_DLL.dll", CallingConvention = CallingConvention.StdCall)]
public static extern int GenerateKeyFromMachine(byte[] key);

[DllImport("AES_DLL.dll", CallingConvention = CallingConvention.StdCall)]
public static extern int AES_EncryptFile(
    [MarshalAs(UnmanagedType.LPWStr)] string input,
    [MarshalAs(UnmanagedType.LPWStr)] string output,
    byte[] key);
```

### Python ctypes

```python
import ctypes

dll = ctypes.WinDLL("AES_DLL.dll")

key = (ctypes.c_uint8 * 32)()
dll.GenerateKeyFromMachine(key)

dll.AES_EncryptFile("plain.txt", "encrypted.bin", key)
dll.AES_DecryptFile("encrypted.bin", "decrypted.txt", key)
```

## 算法与安全

- **AES-256**：14 轮加密，密钥长度 256 位
- **CBC 模式**：每次加密生成随机 16 字节初始化向量 (IV)
- **PKCS7 填充**：兼容任意长度数据
- **密钥派生**：MAC 地址 → SHA-256 → 32 字节密钥
- **文件格式**：`[16B IV][密文]`，IV 随机生成，无密钥无法解密

## 项目结构

```
AES_DLL/
├── AES.h / AES.cpp        # AES-256 核心算法 (S-box, 密钥扩展, CBC)
├── AES_DLL.h / AES_DLL.cpp # DLL 导出接口
├── dllmain.cpp             # DLL 入口点
├── CMakeLists.txt          # CMake 构建脚本
├── AES_DLL.vcxproj         # Visual Studio 项目文件
└── .gitignore
```

## 许可证

MIT License
