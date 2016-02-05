# http2

HTTP/2 connector for tornado


#### Dependencies:
    
    h2==2.1.0
    tornado>=4.0
    CPython>=2.7.10 (not required for h2c, as secure=False)


#### Example Usage:

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
