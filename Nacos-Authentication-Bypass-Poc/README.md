# 简介
Nacos身份认证绕过漏洞

# 声明
此工具仅限授权安全测试使用,禁止非法攻击未授权站点

# 漏洞信息
Nacos 身份认证绕过漏洞，开源服务管理平台 Nacos在默认配置下未对 token.secret.key 进行修改，导致远程攻击者可以绕过密钥认证进入后台，造成系统受控等后果。

# 使用教程

参数

```
python3 Nacos-authentication-bypass.py -h

usage: Nacos-authentication-bypass.py [-h] [-rh remote_host] [-f file_path] [-o outfile_path]

Nacos-authentication-bypass Poc by atk7r

options:
  -h, --help            show this help message and exit
  -rh remote_host, --rhost remote_host
                        Please input host to scan.
  -f file_path, --file file_path
                        Please input file path to scan.
  -o outfile_path, --outfile outfile_path
                        Please input path and filename for output file.

```

单个扫描（一定要是ip或者域名，后面可以加端口）

```
python3 Nacos-authentication-bypass.py -rh 192.168.0.1
python3 Nacos-authentication-bypass.py -rh 192.168.0.1:8088

python3 Nacos-authentication-bypass.py -rh www.abc.com
python3 Nacos-authentication-bypass.py -rh www.abc.com:8088
```

批量扫描（url.txt的内容一定要是ip或者域名，后面可以加端口）

```
python3 Nacos-authentication-bypass.py -f url.txt -o outfile.txt
```

# nuclei

工具地址：https://github.com/projectdiscovery/nuclei

```
#单个
nuclei.exe -u http://192.168.0.1:8088/ -t Nacos-authentication-bypass.yaml -stats

#批量
nuclei.exe -l url.txt -t Nacos-authentication-bypass.yaml -stats
```
