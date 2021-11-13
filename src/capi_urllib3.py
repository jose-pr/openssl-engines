import ssl
from OpenSSL import crypto

import urllib3.contrib.pyopenssl as pyopenssl
import urllib3

from openssl_engines import CAPI_LIST_DISP_FMT, CAPIEngine

_ca_certs=None

def capi_root_certs(reload:bool = False):
    global _ca_certs
    if not _ca_certs or reload:
        with CAPIEngine() as capi:
            _ca_certs = [ crypto.load_certificate(crypto.FILETYPE_PEM, cert.decode()) for cert in capi.list_certs(store="ROOT", format=CAPI_LIST_DISP_FMT.PEM)]
    return _ca_certs

class WindowsSSLContext(pyopenssl.PyOpenSSLContext):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.options = ssl.OP_NO_TLSv1_1
        store= self._ctx.get_cert_store()
        for cert in capi_root_certs():
            store.add_cert(cert)
        self._capi = CAPIEngine()
        self._ctx.set_client_cert_engine(self._capi)
    def __del__(self):
        self._capi.free()

WAS_PYOPENSSL = urllib3.util.IS_PYOPENSSL

def inject_into_urllib3():
    global WAS_PYOPENSSL
    prev = urllib3.util.ssl_.SSLContext
    if not urllib3.util.IS_PYOPENSSL:
        pyopenssl.inject_into_urllib3()
    else:
        WAS_PYOPENSSL = True
    if urllib3.util.IS_PYOPENSSL:
        urllib3.util.SSLContext = WindowsSSLContext
        urllib3.util.ssl_.SSLContext = WindowsSSLContext
    return prev

def extract_from_urllib3(context):
    global WAS_PYOPENSSL
    if not WAS_PYOPENSSL:
        pyopenssl.extract_from_urllib3()
    elif not context:
        context = pyopenssl.PyOpenSSLContext
    if context:
        WAS_PYOPENSSL = None
        urllib3.util.SSLContext = context
        urllib3.util.ssl_.SSLContext = context


