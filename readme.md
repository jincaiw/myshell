# 日常运维 python 脚本和 shell 脚本

## 1. python 脚本使用说明

使用脚本前，需要安装python， 配置运行环境，安装需要的依赖包，脚本在Python 3.12.6 下测试运行没有问题。

### 1.1 Windows 运行环境配置

**（1）下载Python安装包**

- 访问Python官方网站：https://www.python.org/downloads/windows/
- 根据你的系统选择相应的安装包（32位或64位）。

**（2）安装Python**

- 运行下载的安装包。
- 勾选“Add Python to PATH”选项，这样Python会被自动添加到系统环境变量中。
- 选择“Customize installation”以自定义安装路径（可选）。
- 完成安装后，打开命令提示符并输入`python --version`或`python3 --version`来验证安装。

**（3）安装pip**

- Python 3.4及以上版本通常自带pip。
- 如果没有，可以从https://bootstrap.pypa.io/get-pip.py 下载get-pip.py脚本。
- 在命令提示符中运行`python get-pip.py`来安装pip。

**（4）安装虚拟环境（推荐）**

- 虚拟环境安装依赖包简单，其其他程序的冲突和错误也可以隔离。
- 使用pip安装virtualenv：`pip install virtualenv`。
- 创建虚拟环境：`virtualenv venv`。
- 激活虚拟环境：
  - 在命令提示符中：`venv\Scripts\activate`。
  - 在PowerShell中：`.\venv\Scripts\Activate.ps1`。

### 1.2 macOS 运行环境配置

**（1）安装Homebrew（可选但推荐）**

- Homebrew是macOS的包管理器，可以简化软件安装。

- 在终端中运行以下命令安装Homebrew：

  ```bash
  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
  ```

**（2）安装Python**

- 使用Homebrew安装Python：`brew install python`。
- 或者从Python官网下载安装包进行安装。

**（3）安装pip**

- Python 3.4及以上版本通常自带pip。
- 验证pip安装：`pip3 --version`。

**（4）安装虚拟环境（推荐）**

- 使用pip安装virtualenv：`pip3 install virtualenv`。
- 创建虚拟环境：`virtualenv venv`。
- 激活虚拟环境：`source venv/bin/activate`。

## 2.Linux shell 脚本使用说明