# -*- coding: utf-8 -*-

"""
copied from https://github.com/bdarnell/tornado_http2/blob/master/tornado_http2/test/benchmark.py

"""

import time

from tornado import gen, log
from tornado.ioloop import IOLoop
from tornado.options import define, options, parse_command_line


from http2 import SimpleAsyncHTTP2Client


log.enable_pretty_logging()

define('n', help='number of queries', default=1000)
define('h', help='host', default='http2.akamai.com')
define('p', help='port', default=None, type=int)
define('s', help='use https, [1|0]', default=True)
define('c', help='max streams concurrency', default=20)


@gen.coroutine
def benchmark():
    client = SimpleAsyncHTTP2Client(
        host=options.h, port=options.p,
        secure=options.s, max_streams=30,
        connect_timeout=5, enable_push=False
    )

    start = time.time()
    futures = []
    for i in range(options.n):
        futures.append(client.fetch('/'))

    yield futures
    end = time.time()
    raise gen.Return(end - start)


def print_result(label, elapsed):
    print('HTTP/%s: %d requests in %0.3fs: %f QPS' % (label, options.n, elapsed,
          options.n / elapsed))


@gen.coroutine
def main():
    options.logging = "warning"
    parse_command_line()

    elapsed = yield benchmark()
    print_result(2, elapsed)

if __name__ == '__main__':
    IOLoop.current().run_sync(main)
