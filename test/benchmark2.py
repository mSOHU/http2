# -*- coding: utf-8 -*-

"""
copied from https://github.com/bdarnell/tornado_http2/blob/master/tornado_http2/test/benchmark.py

"""

import time

from tornado.ioloop import IOLoop
from tornado.options import define, options, parse_command_line, enable_pretty_logging


from http2 import SimpleAsyncHTTP2Client


enable_pretty_logging()

define('n', help='number of queries', default=1000)
define('h', help='host', default='http2.akamai.com')
define('p', help='port', default=None, type=int)
define('s', help='use https, [1|0]', default=True)
define('c', help='max streams concurrency', default=30)

done_count = [0]
io_loop = IOLoop.instance()


def callback(value):
    done_count[0] += 1
    if done_count[0] == options.n:
        io_loop.stop()
        elapsed = time.time() - start_time
        print 'HTTP/2: %d requests in %0.3fs: %f QPS' % (options.n, elapsed,
              options.n / elapsed)

if __name__ == '__main__':
    options.logging = "info"
    parse_command_line()

    client = SimpleAsyncHTTP2Client(
        host=options.h, port=options.p,
        secure=options.s, max_streams=30,
        connect_timeout=5, enable_push=False
    )

    start_time = time.time()
    for i in range(options.n):
        io_loop.add_callback(lambda: client.fetch('/', callback=callback))
    io_loop.start()
