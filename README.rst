=====
http2
=====

HTTP/2 client for tornado


Features
--------

- connect_timeout & request_timeout supporting
- push streams
- h2 & h2c supporting
- auto-reconnect to server with back-off
- stream multiplexing
- stream concurrency negotiating
- SNI supporting in tornado2
- gzip supporting


Non-features
------------

- web server, dispatcher, cookie, etc
- HTTP/2 upgrade
- follow redirections


WIP
---

- RST_STREAM in body producer
- RST_STREAM after timeout
- close client connection
- pushed streams as future
- healthy check
- flow window manager
- support HTTPRequest.body_producer


Dependencies
------------

- h2>=2.1.0
- tornado>=4.0 or tornado==2.4.1
- CPython>=2.7.10 (not required for h2c, as secure=False)
- certifi for tornado==2.4.1
- backports.ssl_match_hostname for tornado==2.4.1


Example Usage
-------------

::

    import tornado.ioloop
    from tornado.httpclient import HTTPRequest
    
    from http2 import SimpleAsyncHTTP2Client
    
    client = SimpleAsyncHTTP2Client(
        host='h2o.examp1e.net', enable_push=True, 
        connect_timeout=1, defaults={'request_timeout': 1}
    )
    
    resp = tornado.ioloop.IOLoop.instance().run_sync(lambda: client.fetch('/'))
    
    print resp
    for pushed_response in resp.pushed_responses:
        print pushed_response.effective_url


Credits
-------

A big thanks to the great library hyper-h2_ from `Cory Benfield`_.  :P

.. _hyper-h2: https://github.com/python-hyper/hyper-h2
.. _`Cory Benfield`: https://github.com/Lukasa
