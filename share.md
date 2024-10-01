# 简介

这是一个命令行文件共享工具，只有一个文件就可以简单使用。

# 特点

- 跨多个平台
- 共享目录、文件和文本
- 接收文件和文本
- 范围请求支持
- 密码共享
- TLS 支持
- Zstd 压缩支持（需要[python-zstandard](https://github.com/indygreg/python-zstandard)库，但可选）
- 二维码支持（需要[python-qrcode](https://github.com/lincolnloop/python-qrcode)库，但可选）

# 使用方法

```
用法: share.py [-b ADDRESS] [-p PORT] [-s] [-r] [-a] [-z] [-t] [-P [PASSWORD]] [-q] [-h] [--certfile CERTFILE] [--keyfile KEYFILE] [--keypass KEYPASS] [arguments ...]

positional arguments:
  arguments             a directory, files or texts

general options:
  -b ADDRESS, --bind ADDRESS
                        bind address [default: all interfaces]
  -p PORT, --port PORT  port [default: 8888]
  -s, --share           share mode (default mode)
  -r, --receive         receive mode, can be used with -s option (only for directory)
  -a, --all             show all files, including hidden ones, only for directory
  -z, --archive         share the directory itself as an archive, only for directory
  -t, --text            for text
  -P [PASSWORD], --password [PASSWORD]
                        access password, if no PASSWORD is specified, the environment variable SHARE_PASSWORD will be used
  -q, --qrcode          show the qrcode
  -h, --help            show this help message and exit

tls options:
  --certfile CERTFILE   cert file
  --keyfile KEYFILE     key file
  --keypass KEYPASS     key password
```

# 截图

![img](https://github.com/beavailable/share/blob/main/screenshot.gif)

# Tips

- 如果您正在共享单个文件，可以使用快捷名称“file”来访问它：

  ```bash
  http://{host}:{port}/file
  ```

  使用“wget”以原始文件名保存：

  ```bash
  wget --content-disposition http://{host}:{port}/file
  ```

  或者使用“curl”：

  ```bash
  curl -OJ http://{host}:{port}/file
  ```

- 要获取文件夹的存档，可以将“.tar.zst”扩展名添加到 URL 中：

  ```bash
  http://{host}:{port}/any/folder.tar.zst
  ```

- 如果您想使用“curl”将文件上传到共享服务器，可以使用：

  ```bash
  curl -F file=@/path/to/file http://{host}:{port}
  # create new folders at the same time
  curl -F file=@/path/to/file http://{host}:{port}/custom/path
  ```

  Or:

  ```bash
  curl -T /path/to/file http://{host}:{port}
  # create new folders at the same time
  curl -T /path/to/file http://{host}:{port}/custom/path/
  # with a different filename
  curl -T /path/to/file http://{host}:{port}/custom/path/custom-filename
  ```