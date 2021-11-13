
import socket
import requests
import pytest

import os, sys, inspect
ourfilename = os.path.abspath(inspect.getfile(inspect.currentframe()))
currentdir = os.path.dirname(ourfilename)
parentdir = os.path.dirname(currentdir)
src=os.path.join(parentdir,"src")
if src not in sys.path:
    sys.path.insert(0, src)
from OpenSSL import SSL
from OpenSSL.SSL import Context as SSLContext
from openssl_engines import *
from capi_urllib3 import *

ctx = SSLContext(SSL.SSLv23_METHOD)

def test_load_dynamic():
    SSLEngine.load_dynamic("capi")

def test_load_by_id():
    SSLEngine.load_by_id("capi")

def test_capi():
    CAPIEngine()

def test_capi_list_certs():
    assert len(capi_root_certs(True)) > 0, "There should be at least 1 certificate in the Trusted Root Certificate store "

def test_urllib3():
    inject_into_urllib3()
    s = requests.Session()

    pki_host=("pki.example.lan" , 9443)

    #Request default session which uses urllib3 default sslcontext 
    r = s.get("https://%s:%s"%pki_host)
    print(r.text)

    #Simple Socker with context
    ctx = WindowsSSLContext(ssl.PROTOCOL_TLS)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(pki_host)
    s = ctx.wrap_socket(s)

    s.sendall("CONNECT %s:%s HTTP/1.0\r\nConnection: close\r\n\r\n"%pki_host)

    print(s.recv(4096).decode())


if __name__ == "__main__":
    test_load_dynamic()
    test_capi_list_certs()
    test_urllib3()