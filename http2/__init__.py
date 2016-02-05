# -*- coding: utf-8 -*-


from tornado import version_info

if version_info[0] >= 4:
    from http2.torando4 import *
else:
    raise NotImplementedError()
