import os
from cffi import FFI
from OpenSSL.SSL import Context as SSLContext, _ffi, _lib as lib

from utils import OutputGrabber

ffi = FFI()
NULL = ffi.NULL
ffi.cdef(
    "int SSL_CTX_set_client_cert_engine(void *ctx, void *e);"
    "int ENGINE_set_default(void *e, unsigned int flags);"
)
libcrypto = ffi.dlopen("libcrypto-1_1.dll")
libssl = ffi.dlopen("libssl-1_1.dll")


class ENGINE_DEFAULT:
    ALL = 0xFFFF

class CAPI_LIST_DISP_FMT:
    SUMMARY = 1
    FRIENDLY_NAME = 2
    FULL = 4
    PEM = 8
    XXX = 16
    PRIV_KEY_INFO = 32


class SSLEngine(object):
    def __init__(self, id: str | FFI.CData) -> None:
        if isinstance(id, str):
            try:
                eng = SSLEngine.load_by_id(id)
            except Exception:
                eng = SSLEngine.load_dynamic(id)
            ptr = eng.ptr
        elif isinstance(id, SSLEngine):
            ptr = id.ptr
        else:
            ptr = id
        self.ptr = ptr

    def init(self):
        if not lib.ENGINE_init(self.ptr):
            self.__exit__()
            raise Exception("Could not initialize engine")

    def free(self):
        lib.ENGINE_free(self.ptr)

    def __enter__(self):
        self.init()
        return self

    def __exit__(self, type, value, traceback):
        self.free()

    def set_default(self, flags: int = ENGINE_DEFAULT.ALL):
        if not libcrypto.ENGINE_set_default(self.ptr, flags):
            self.free()
            raise Exception(
                "Not able to set engine as default for all flags:%s" % flags
            )

    def ctrl_cmd_string(
        self,
        cmd: str,
        value: str | None = None,
        optional: bool = False,
        capture: bool = False,
    ) -> None | bytes:
        io: None | OutputGrabber = None
        if capture:
            io = OutputGrabber(threaded=True)
            io.start()
        if not lib.ENGINE_ctrl_cmd_string(
            self.ptr,
            cmd.encode("utf-8"),
            NULL if value == None else value.encode("utf-8"),
            1 if optional else 0,
        ):
            if capture:
                io.stop()
            raise Exception(
                "Error with engine string control command: %s%s"
                % (cmd, "" if value == None else ":" + value)
            )
        if capture:
            io.stop()
            return io.captured

    def load_by_id(id: str):
        if not id:
            raise ValueError("Id value must be provided")
        lib.ENGINE_load_builtin_engines()
        ptr = lib.ENGINE_by_id(id.encode())
        if ptr == NULL:
            raise ValueError("Could not load the {0} engine by id".format(id))
        return SSLEngine(ptr)

    def load_dynamic(
        id: str,
        path: str = None,
        search_path: str = None,
        check_version: bool = True,
    ):

        if not id:
            raise ValueError("Id value must be provided")

        dyn = SSLEngine.load_by_id("dynamic")
        dyn.ctrl_cmd_string("ID", id)

        if path:
            dyn.ctrl_cmd_string("SO_PATH", path)

        dyn.ctrl_cmd_string("LIST_ADD", "1")

        if not check_version:
            dyn.ctrl_cmd_string("NO_VCHECK", "1")

        if search_path == None and path == None and "OPENSSL_ENGINES" in os.environ:
            search_path = os.environ ["OPENSSL_ENGINES"]

        if search_path:
            dyn.ctrl_cmd_string("DIR_LOAD", "2")
            dyn.ctrl_cmd_string("DIR_ADD", search_path)

        dyn.ctrl_cmd_string("LOAD")
        return dyn


class CAPIEngine(SSLEngine):
    def __init__(self, src: FFI.CData | str | None = None) -> None:
        if not src:
            src = "capi"
        super().__init__(SSLEngine(src) if isinstance(src, str) else src)

    def set_store(self, name: str):
        self.ctrl_cmd_string("store_name", name)

    def list_certs(
        self, store: str | None = None, format: int | None = None
    ) -> list[bytes]:
        if format:
            self.ctrl_cmd_string("list_options", str(format))
        if store:
            self.set_store(store)
        return [
            cert.split(sep=b"\n", maxsplit=1)[1]
            for cert in self.ctrl_cmd_string("list_certs", capture=True)
            .strip(b"\n")
            .split(b"\nCertificate ")
        ]


def set_client_cert_engine(self: SSLContext, engine: FFI.CData | SSLEngine):
    if not libssl.SSL_CTX_set_client_cert_engine(
        self._context, engine.ptr if isinstance(engine, SSLEngine) else engine
    ):
        raise Exception("Was not able to set client cert engine")


SSLContext.set_client_cert_engine = set_client_cert_engine
