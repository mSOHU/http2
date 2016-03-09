# -*- coding: utf-8 -*-

import sys


# patch struct.unpack to accept memoryview object
# for python < 2.7.5
if sys.version < (2, 7, 5):
    import struct
    _unpack = struct.unpack

    def unpack(fmt, data):
        if isinstance(data, memoryview):
            return _unpack(fmt, data.tobytes())
        else:
            return _unpack(fmt, data)
    struct.unpack = unpack


try:
    from tornado import version_info
except ImportError:
    pass
else:
    if version_info[0] == 4:
        from http2.tornado4 import *
    elif version_info[0] == 2:
        from http2.tornado2 import *
