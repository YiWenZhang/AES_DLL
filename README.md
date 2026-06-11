# AES_DLL — AES-256 加密动态链接库

跨语言可调用的 AES-256-CBC 加密库，支持文件和字符串加解密，基于机器特征（MAC 地址）派生密钥。

---

## Python 安装（推荐）

像 PyTorch 一样，一行安装，一行导入：

```bash
# 从 GitHub 直接安装（需要安装 MSVC / Visual Studio）
pip install git+https://github.com/YiWenZhang/AES_DLL.git
```

安装后即可使用：

```python
import aesdll

# 基于本机 MAC 地址生成密钥
key = aesdll.generate_key_from_machine()

# 加密文件
aesdll.encrypt_file("秘密.txt", "秘密.enc", key)

# 解密文件
aesdll.decrypt_file("秘密.enc", "解密.txt", key)

# 加密字符串
token = aesdll.encrypt_string("hello world", key)
print(token)  # 十六进制密文

# 解密字符串
original = aesdll.decrypt_string(token, key)
print(original)  # "hello world"
```

> **注意**：从 Git 安装时会自动编译 DLL，需要本机装有 Visual Studio（MSVC）。如果不想编译，可以从 [Releases](https://github.com/YiWenZhang/AES_DLL/releases) 下载预编译的 DLL，手动放到 `aesdll/` 目录下即可。


## C/C++ 使用

### 隐式链接

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

### 显式链接（LoadLibrary）

```c
HMODULE hDll = LoadLibraryW(L"AES_DLL.dll");
typedef int (__stdcall *EncryptFile_t)(const wchar_t*, const wchar_t*, const uint8_t*);
EncryptFile_t AES_EncryptFile = (EncryptFile_t)GetProcAddress(hDll, "AES_EncryptFile");
AES_EncryptFile(L"plain.txt", L"encrypted.bin", key);
FreeLibrary(hDll);
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

### Python 原生 ctypes（不用 pip 包）

```python
import ctypes
dll = ctypes.WinDLL("AES_DLL.dll")
key = (ctypes.c_uint8 * 32)()
dll.GenerateKeyFromMachine(key)
dll.AES_EncryptFile("plain.txt", "encrypted.bin", key)
dll.AES_DecryptFile("encrypted.bin", "decrypted.txt", key)
```

---

## 编译 DLL（开发者）

### 方式一：Visual Studio / MSBuild

```bash
msbuild AES_DLL.vcxproj -p:Configuration=Release -p:Platform=x64
```

产物在 `x64/Release/AES_DLL.dll` 和 `AES_DLL.lib`。

### 方式二：CMake

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build .
```

---

## API 接口

所有函数均使用 `__stdcall` 调用约定，`extern "C"` 导出。

| 函数 | 说明 |
|------|------|
| `GetMacAddress()` | 获取本机 MAC 地址（十六进制大写字符串，无分隔符） |
| `GenerateKeyFromMachine(key[32])` | 从 MAC 地址派生 32 字节 AES-256 密钥 |
| `AES_EncryptFile(in, out, key[32])` | 加密文件，输出格式：`[16字节IV][密文]` |
| `AES_DecryptFile(in, out, key[32])` | 解密文件，还原明文 |
| `EncryptString(text, key[32])` | 加密字符串，返回十六进制密文 |
| `DecryptString(hex, key[32])` | 解密十六进制密文，还原明文字符串 |
| `FreeString(str)` | 释放 DLL 分配的字符串内存 |

---

## 算法与安全

- **AES-256**：14 轮加密，密钥长度 256 位
- **CBC 模式**：每次加密生成随机 16 字节初始化向量 (IV)
- **PKCS7 填充**：兼容任意长度数据
- **密钥派生**：MAC 地址 → SHA-256 → 32 字节密钥
- **文件格式**：`[16B IV][密文]`，IV 随机生成，无密钥无法解密

---

## 项目结构

```
AES_DLL/
├── aesdll/                  # Python 包
│   ├── __init__.py          # 公开 API
│   └── _native.py           # ctypes 绑定层
├── AES.h / AES.cpp          # AES-256 核心算法
├── AES_DLL.h / AES_DLL.cpp  # DLL 导出接口
├── dllmain.cpp              # DLL 入口点
├── pyproject.toml            # Python 包元数据
├── setup.py                  # 自动编译 DLL 的安装脚本
├── CMakeLists.txt            # CMake 构建脚本
├── AES_DLL.vcxproj           # Visual Studio 项目文件
└── .gitignore
```

---

## 发布流程

### 推送到 GitHub

```bash
# 1. 在 github.com/new 创建一个空仓库（不要勾选 README / .gitignore）

# 2. 推送代码
git remote add origin https://github.com/YiWenZhang/AES_DLL.git
git branch -M main
git push -u origin main
```

### 发布编译好的 DLL（GitHub Releases）

```bash
# 编译
msbuild AES_DLL.vcxproj -p:Configuration=Release -p:Platform=x64

# 打包
cd x64/Release
zip AES_DLL_v1.0.0.zip AES_DLL.dll AES_DLL.lib
```

然后在 GitHub 仓库页面 → **Releases** → **Create a new release**，上传 zip 文件。

### 发布到 PyPI（可选）

这样别人就能 `pip install aes-dll` 直接安装：

```bash
# 1. 安装打包工具
pip install build twine

# 2. 构建 wheel
python -m build

# 3. 上传到 PyPI（需要先在 pypi.org 注册账号）
twine upload dist/*
```

上传成功后，任何人都可以：

```bash
pip install aes-dll
```

```python
import aesdll
```

---

## 许可证

MIT License
