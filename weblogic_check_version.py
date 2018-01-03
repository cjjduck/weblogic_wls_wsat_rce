#!/usr/bin/env python
#coding:utf-8
import re
import time
import socket
import requests

headers = {'User-Agent':'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)'}
timeout = 5

'''
check weblogic by 404
'''
def check_weblogic(host,port):
    url = 'http://{}:{}/conso1e'.format(host,port)
    try:
        r = requests.get(url,headers = headers ,timeout =timeout)
        if r.status_code == 404 and 'From RFC 2068' in r.text:
            return check_weblogic_version(host,port)
        else:
            return (False,'not checked')
    except requests.exceptions.ConnectionError:
        return (False,'ConnectionError')
    except Exception,e:
        #raise
        return (False,str(e))

'''
get weblogic version by t3
'''
def check_weblogic_version(host,port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (host, port)
    sock.settimeout(timeout)
    try:
        sock.connect(server_address)
        # Send headers
        send_count = 0
        headers = 't3 11.1.2\nAS:2048\nHL:19\n\n'
        # print 'sending Hello'
        sock.sendall(headers)
        data = ''
        #receive data and check version:
        try:
            while True:
                data += sock.recv(1024).strip()
                #print data
                if not data.startswith('HELO'):
                    msg = 't3_send exception: receive HELO fail!'
                    return (False, msg)
                m = re.findall(r'HELO:(\d+\.\d+\.\d+\.\d+)\.',data)
                if m:
                    return (True,m[0])
                time.sleep(0.1)
        except socket.timeout:
            return (False,'unknown version') 
    except Exception, e:
        #raise
        msg = "t3_send exception:%s" % e
        return (False, msg)
    finally:
        sock.close()


def main():
    with open('1.txt') as f:
        for ip in f:
            print ip,check_weblogic(ip.strip(),7001)
        
if __name__ == '__main__':
    main()
