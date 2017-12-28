# weblogic_wls_wsat_rce

**Weblogic wls-wsat组件反序列化漏洞(CVE-2017-10271)利用脚本，参考[https://github.com/s3xy/CVE-2017-10271](https://github.com/s3xy/CVE-2017-10271)修改。**




+ 命令执行并回显
+ 直接上传shell
+ 在linux下weblogic 10.3.6.0测试OK

**使用方法及参数**

+ python weblogic_wls_wsat_exp.py -t 172.16.80.131:7001

```bash
usage: weblogic_wls_wsat_exp.py [-h] -t TARGET [-c CMD] [-o OUTPUT] [-s SHELL]

optional arguments:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        weblogic ip and port(eg -> 172.16.80.131:7001)
  -c CMD, --cmd CMD     cmd to execute,default is id
  -o OUTPUT, --output OUTPUT
                        output file name,default is output.txt
  -s SHELL, --shell SHELL
                        getshell by upload jsp file
```