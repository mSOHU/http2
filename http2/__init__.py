# -*- coding: utf-8 -*-

try:
    from tornado import version_info
except ImportError:
    pass
else:
    if version_info[0] == 4:
        from http2.tornado4 import *
