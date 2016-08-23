# -*- coding: utf-8 -*-

import io
import ssl
import sys
import copy
import time
import zlib
import base64
import socket
import httplib
import logging
import urlparse
import functools
import collections

import h2.errors
import h2.events
import h2.settings
import h2.connection
import h2.exceptions
from tornado import (
    httputil, stack_context, iostream,
    simple_httpclient,
)
from tornado.escape import _unicode, utf8
from tornado.httpclient import (
    HTTPResponse, HTTPError, HTTPRequest
)


if hasattr(ssl, 'match_hostname') and hasattr(ssl, 'CertificateError'):  # python 3.2+
    ssl_match_hostname = ssl.match_hostname
    SSLCertificateError = ssl.CertificateError
elif ssl is None:
    ssl_match_hostname = SSLCertificateError = None
else:
    import backports.ssl_match_hostname
    ssl_match_hostname = backports.ssl_match_hostname.match_hostname
    SSLCertificateError = backports.ssl_match_hostname.CertificateError

try:
    import certifi
except ImportError:
    certifi = None


def _default_ca_certs():
    if certifi is None:
        raise Exception("The 'certifi' package is required to use https "
                        "in SimpleAsyncHTTP2Client")
    return certifi.where()

logger = logging.getLogger(__name__)
ResponseStartLine = collections.namedtuple(
    'ResponseStartLine', ['version', 'code', 'reason'])

__all__ = [
    'HTTP2Response', 'HTTP2Error', 'HTTP2ConnectionTimeout',
    'HTTP2ConnectionClosed', 'SimpleAsyncHTTP2Client',
]


class HTTP2Response(HTTPResponse):
    def __init__(self, *args, **kwargs):
        self.pushed_responses = kwargs.pop('pushed_responses', [])
        self.new_request = kwargs.pop('new_request', None)
        self.reason = kwargs.pop('reason', None)
        super(HTTP2Response, self).__init__(*args, **kwargs)


class HTTP2Error(HTTPError):
    pass


class HTTP2ConnectionTimeout(HTTP2Error):
    def __init__(self, time_cost=None):
        self.time_cost = time_cost


class HTTP2ConnectionClosed(HTTP2Error):
    def __init__(self, reason=None):
        super(HTTP2ConnectionClosed, self).__init__(599)
        self.reason = reason


class _RequestTimeout(Exception):
    pass

# These are the keyword arguments to ssl.wrap_socket that must be translated
# to their SSLContext equivalents (the other arguments are still passed
# to SSLContext.wrap_socket).
_SSL_CONTEXT_KEYWORDS = frozenset(['ssl_version', 'certfile', 'keyfile',
                                   'cert_reqs', 'ca_certs', 'ciphers'])


def ssl_options_to_context(ssl_options):
    """Try to convert an ``ssl_options`` dictionary to an
    `~ssl.SSLContext` object.

    The ``ssl_options`` dictionary contains keywords to be passed to
    `ssl.wrap_socket`.  In Python 3.2+, `ssl.SSLContext` objects can
    be used instead.  This function converts the dict form to its
    `~ssl.SSLContext` equivalent, and may be used when a component which
    accepts both forms needs to upgrade to the `~ssl.SSLContext` version
    to use features like SNI or NPN.
    """
    if isinstance(ssl_options, dict):
        assert all(k in _SSL_CONTEXT_KEYWORDS for k in ssl_options), ssl_options
    if (not hasattr(ssl, 'SSLContext') or
            isinstance(ssl_options, ssl.SSLContext)):
        return ssl_options
    context = ssl.SSLContext(
        ssl_options.get('ssl_version', ssl.PROTOCOL_SSLv23))
    if 'certfile' in ssl_options:
        context.load_cert_chain(ssl_options['certfile'], ssl_options.get('keyfile', None))
    if 'cert_reqs' in ssl_options:
        context.verify_mode = ssl_options['cert_reqs']
    if 'ca_certs' in ssl_options:
        context.load_verify_locations(ssl_options['ca_certs'])
    if 'ciphers' in ssl_options:
        context.set_ciphers(ssl_options['ciphers'])
    if hasattr(ssl, 'OP_NO_COMPRESSION'):
        # Disable TLS compression to avoid CRIME and related attacks.
        # This constant wasn't added until python 3.3.
        context.options |= ssl.OP_NO_COMPRESSION
    return context


class GzipDecompressor(object):
    """Streaming gzip decompressor.

    The interface is like that of `zlib.decompressobj` (without some of the
    optional arguments, but it understands gzip headers and checksums.
    """
    def __init__(self):
        # Magic parameter makes zlib module understand gzip header
        # http://stackoverflow.com/questions/1838699/how-can-i-decompress-a-gzip-stream-with-zlib
        # This works on cpython and pypy, but not jython.
        self.decompressobj = zlib.decompressobj(16 + zlib.MAX_WBITS)

    def decompress(self, value, max_length=None):
        """Decompress a chunk, returning newly-available data.

        Some data may be buffered for later processing; `flush` must
        be called when there is no more input data to ensure that
        all data was processed.

        If ``max_length`` is given, some input data may be left over
        in ``unconsumed_tail``; you must retrieve this value and pass
        it back to a future call to `decompress` if it is not empty.
        """
        return self.decompressobj.decompress(value, max_length)

    @property
    def unconsumed_tail(self):
        """Returns the unconsumed portion left over
        """
        return self.decompressobj.unconsumed_tail

    def flush(self):
        """Return any remaining buffered data not yet returned by decompress.

        Also checks for errors such as truncated input.
        No other methods may be called on this object after `flush`.
        """
        return self.decompressobj.flush()


class SimpleAsyncHTTPClientWithTimeout(simple_httpclient.SimpleAsyncHTTPClient):
    def initialize(self, *args, **kwargs):
        super(SimpleAsyncHTTPClientWithTimeout, self).initialize(*args, **kwargs)

        # all pending requests
        self.waiting = {}

    def fetch(self, request, callback, **kwargs):
        if not isinstance(request, HTTPRequest):
            request = HTTPRequest(url=request, **kwargs)
        # We're going to modify this (to add Host, Accept-Encoding, etc),
        # so make sure we don't modify the caller's object.  This is also
        # where normal dicts get converted to HTTPHeaders objects.
        request.headers = httputil.HTTPHeaders(request.headers)
        callback = stack_context.wrap(callback)

        key = object()
        self.queue.append((key, request, callback))

        if not len(self.active) < self.max_clients:
            timeout_handle = self.io_loop.add_timeout(
                time.time() + min(request.connect_timeout,
                                  request.request_timeout),
                functools.partial(self._on_timeout, key))
        else:
            timeout_handle = None

        self.waiting[key] = (request, callback, timeout_handle)
        self._process_queue()
        if self.queue:
            logging.debug(
                'max_clients limit reached, request queued. '
                '%d active, %d queued requests.' % (
                    len(self.active), len(self.queue))
            )

    def _remove_timeout(self, key):
        if key in self.waiting:
            request, callback, timeout_handle = self.waiting[key]
            if timeout_handle is not None:
                self.io_loop.remove_timeout(timeout_handle)
            del self.waiting[key]

    def _on_timeout(self, key):
        request, callback, timeout_handle = self.waiting[key]
        self.queue.remove((key, request, callback))
        timeout_response = HTTPResponse(
            request, 599, error=HTTPError(599, "Timeout"),
            request_time=time.time() - request.start_time)
        self.io_loop.add_callback(callback, timeout_response)
        del self.waiting[key]

    def _process_queue(self):
        with stack_context.NullContext():
            while self.queue and len(self.active) < self.max_clients:
                key, request, callback = self.queue.popleft()
                if key not in self.waiting:
                    continue
                self._remove_timeout(key)
                self.active[key] = (request, callback)
                release_callback = functools.partial(self._release_fetch, key)
                self._handle_request(request, release_callback, callback)

    def _handle_request(self, request, release_callback, callback):
        simple_httpclient._HTTPConnection(
            self.io_loop, self, request, release_callback,
            callback, self.max_buffer_size)

    @classmethod
    def setup_default(cls):
        simple_httpclient.AsyncHTTPClient.configure(cls)


class SimpleAsyncHTTP2Client(SimpleAsyncHTTPClientWithTimeout):
    MAX_CONNECTION_BACKOFF = 10
    CONNECTION_BACKOFF_STEP = 1
    CLIENT_REGISTRY = {}

    def __new__(cls, *args, **kwargs):
        force_instance = kwargs.pop('force_instance', False)
        host = kwargs['host']
        if force_instance or host not in cls.CLIENT_REGISTRY:
            client = simple_httpclient.SimpleAsyncHTTPClient.__new__(cls, *args, force_instance=True, **kwargs)
            cls.CLIENT_REGISTRY.setdefault(host, client)
        else:
            client = cls.CLIENT_REGISTRY[host]

        return client

    def initialize(self, io_loop, host, port=None, max_streams=200,
                   hostname_mapping=None, max_buffer_size=104857600,
                   resolver=None, defaults=None, secure=True,
                   cert_options=None, enable_push=False, connect_timeout=20,
                   initial_window_size=65535, **conn_kwargs):
        # initially, we disables stream multiplexing and wait the settings frame
        super(SimpleAsyncHTTP2Client, self).initialize(
            io_loop=io_loop, max_clients=1,
            hostname_mapping=hostname_mapping, max_buffer_size=max_buffer_size,
        )
        self.host = host
        self.port = port
        self.secure = secure
        self.max_streams = max_streams
        self.enable_push = bool(enable_push)
        self.initial_window_size = initial_window_size

        self.connect_timeout = connect_timeout
        self.connection_factory = _HTTP2ConnectionFactory(
            io_loop=self.io_loop, host=host, port=port,
            max_buffer_size=self.max_buffer_size, secure=secure,
            cert_options=cert_options, connect_timeout=self.connect_timeout
        )

        # open connection
        self.connection = None
        self.io_stream = None

        # back-off
        self.next_connect_time = 0
        self.connection_backoff = self.CONNECTION_BACKOFF_STEP

        self.connection_factory.make_connection(
            self._on_connection_ready, self._on_connection_close)

    def _adjust_settings(self, event):
        logger.debug('settings updated: %r', event.changed_settings)
        settings = event.changed_settings.get(h2.settings.MAX_CONCURRENT_STREAMS)
        if settings:
            self.max_clients = min(settings.new_value, self.max_streams)
            if settings.new_value > settings.original_value:
                self._process_queue()

    def _on_connection_close(self, io_stream, reason):
        if self.io_stream is not io_stream:
            return

        connection = self.connection
        self.io_stream = None
        self.connection = None

        if connection is not None:
            connection.on_connection_close(io_stream.error)

        # schedule back-off
        now_time = time.time()
        self.next_connect_time = max(
            self.next_connect_time,
            now_time + self.connection_backoff)

        self.connection_backoff = min(
            self.connection_backoff + self.CONNECTION_BACKOFF_STEP,
            self.MAX_CONNECTION_BACKOFF)

        if io_stream is None:
            logger.info(
                'Connection to %s:%u failed due: %r. Reconnect in %.2f seconds',
                self.host, self.port, reason, self.next_connect_time - now_time)
        else:
            logger.info(
                'Connection to %s:%u closed due: %r. Reconnect in %.2f seconds',
                self.host, self.port, reason, self.next_connect_time - now_time)

        self.io_loop.add_timeout(
            self.next_connect_time, functools.partial(
                self.connection_factory.make_connection,
                self._on_connection_ready, self._on_connection_close
            ))

        # move active request to pending
        for key, (request, callback) in self.active.items():
            self.queue.appendleft((key, request, callback))

        self.active.clear()

    def _connection_terminated(self, event):
        self._on_connection_close(
            self.io_stream, 'Server requested, code: 0x%x' % event.error_code)

    def _on_connection_ready(self, io_stream):
        # reset back-off, prevent reconnect within back-off period
        self.next_connect_time += self.connection_backoff
        self.connection_backoff = 0

        self.io_stream = io_stream
        self.connection = _HTTP2ConnectionContext(
            io_stream=io_stream, secure=self.secure,
            enable_push=self.enable_push,
            max_buffer_size=self.max_buffer_size,
            initial_window_size=self.initial_window_size,
        )
        self.connection.add_event_handler(
            h2.events.RemoteSettingsChanged, self._adjust_settings
        )
        self.connection.add_event_handler(
            h2.events.ConnectionTerminated, self._connection_terminated
        )
        self._process_queue()

    def _process_queue(self):
        if not self.connection:
            return

        super(SimpleAsyncHTTP2Client, self)._process_queue()

    def _handle_request(self, request, release_callback, final_callback):
        _HTTP2Stream(
            self.io_loop, self.connection, request,
            self.host, release_callback, final_callback
        )


class _SSLIOStream(iostream.SSLIOStream):
    def __init__(self, *args, **kwargs):
        self.hostname = kwargs.pop('hostname')
        super(_SSLIOStream, self).__init__(*args, **kwargs)

    def _handle_connect(self):
        # When the connection is complete, wrap the socket for SSL
        # traffic.  Note that we do this by overriding _handle_connect
        # instead of by passing a callback to super().connect because
        # user callbacks are enqueued asynchronously on the IOLoop,
        # but since _handle_events calls _handle_connect immediately
        # followed by _handle_write we need this to be synchronous.
        self.socket = self.ssl_wrap_socket(
            self.socket, self._ssl_options,
            server_hostname=self.hostname,
            server_side=False,
            do_handshake_on_connect=False
        )
        super(iostream.SSLIOStream, self)._handle_connect()

    @classmethod
    def ssl_wrap_socket(cls, s, ssl_options, server_hostname=None, **kwargs):
        """Returns an ``ssl.SSLSocket`` wrapping the given socket.

        ``ssl_options`` may be either a dictionary (as accepted by
        `ssl_options_to_context`) or an `ssl.SSLContext` object.
        Additional keyword arguments are passed to ``wrap_socket``
        (either the `~ssl.SSLContext` method or the `ssl` module function
        as appropriate).
        """
        context = ssl_options_to_context(ssl_options)
        if hasattr(ssl, 'SSLContext') and isinstance(context, ssl.SSLContext):
            if server_hostname is not None and getattr(ssl, 'HAS_SNI'):
                # Python doesn't have server-side SNI support so we can't
                # really unittest this, but it can be manually tested with
                # python3.2 -m tornado.httpclient https://sni.velox.ch
                return context.wrap_socket(s, server_hostname=server_hostname,
                                           **kwargs)
            else:
                return context.wrap_socket(s, **kwargs)
        else:
            return ssl.wrap_socket(s, **dict(context, **kwargs))


class _HTTP2ConnectionFactory(object):
    def __init__(self, io_loop, host, port, max_buffer_size,
                 secure=True, cert_options=None, connect_timeout=None):
        self.io_loop = io_loop
        self.max_buffer_size = max_buffer_size
        self.cert_options = collections.defaultdict(lambda: None, **cert_options or {})
        if port is None:
            port = 443 if secure else 80

        self.host = host
        self.port = port
        self.secure = secure
        self.connect_timeout = connect_timeout
        self.ssl_options = self._get_ssl_options(self.cert_options) if secure else None

    def make_connection(self, ready_callback, close_callback):
        if self.connect_timeout:
            timed_out = [False]
            start_time = time.time()

            def _on_timeout():
                timed_out[0] = True
                close_callback(
                    io_stream=None,
                    reason=HTTP2ConnectionTimeout(time.time() - start_time)
                )

            def _on_connect(_stream):
                if timed_out[0]:
                    _stream.close()
                    return
                self.io_loop.remove_timeout(timeout_handle)
                self._on_connect(_stream, ready_callback, close_callback)

            timeout_handle = self.io_loop.add_timeout(
                start_time + self.connect_timeout, _on_timeout)

        else:
            _on_connect = functools.partial(
                self._on_connect,
                ready_callback=ready_callback,
                close_callback=close_callback,
            )

        with stack_context.ExceptionStackContext(
                functools.partial(self._handle_exception, close_callback)):

            addr_info = socket.getaddrinfo(
                self.host, self.port, socket.AF_UNSPEC,
                socket.SOCK_STREAM, 0, 0)
            af, sock_type, proto, canon_name, sockaddr = addr_info[0]

            if self.secure:
                io_stream = _SSLIOStream(
                    socket.socket(af, sock_type, proto),
                    hostname=self.host,
                    io_loop=self.io_loop,
                    ssl_options=self.ssl_options,
                    max_buffer_size=self.max_buffer_size
                )
            else:
                io_stream = iostream.IOStream(
                    socket.socket(af, sock_type, proto),
                    io_loop=self.io_loop,
                    max_buffer_size=self.max_buffer_size)

            io_stream.connect(sockaddr, functools.partial(_on_connect, io_stream))

    @classmethod
    def _handle_exception(cls, close_callback, typ, value, tb):
        close_callback(io_stream=None, reason=value)
        return True

    @classmethod
    def _get_ssl_options(cls, cert_options):
        ssl_options = {}
        if cert_options['validate_cert']:
            ssl_options["cert_reqs"] = ssl.CERT_REQUIRED
        if cert_options['ca_certs'] is not None:
            ssl_options["ca_certs"] = cert_options['ca_certs']
        else:
            ssl_options["ca_certs"] = _default_ca_certs()
        if cert_options['client_key'] is not None:
            ssl_options["keyfile"] = cert_options['client_key']
        if cert_options['client_cert'] is not None:
            ssl_options["certfile"] = cert_options['client_cert']

        # according to REC 7540:
        # deployments of HTTP/2 that use TLS 1.2 MUST
        # support TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        ssl_options["ciphers"] = "ECDH+AESGCM"
        ssl_options["ssl_version"] = ssl.PROTOCOL_TLSv1_2
        ssl_options = ssl_options_to_context(ssl_options)
        ssl_options.set_alpn_protocols(['h2'])
        return ssl_options

    def _on_connect(self, io_stream, ready_callback, close_callback):
        if self.secure:
            if not self._verify_cert(io_stream.socket.getpeercert()):
                io_stream.close()
                return

        io_stream.set_close_callback(lambda: close_callback(io_stream, io_stream.error))
        self.io_loop.add_callback(functools.partial(ready_callback, io_stream))
        io_stream.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def _verify_cert(self, peer_cert):
        """Returns True if peercert is valid according to the configured
        validation mode and hostname.

        The ssl handshake already tested the certificate for a valid
        CA signature; the only thing that remains is to check
        the hostname.
        """
        verify_mode = self.ssl_options.verify_mode
        assert verify_mode in (ssl.CERT_NONE, ssl.CERT_REQUIRED, ssl.CERT_OPTIONAL)
        if verify_mode == ssl.CERT_NONE or self.host is None:
            return True

        if peer_cert is None and verify_mode == ssl.CERT_REQUIRED:
            logger.warning("No SSL certificate given")
            return False
        try:
            ssl_match_hostname(peer_cert, self.host)
        except SSLCertificateError:
            logger.warning("Invalid SSL certificate", exc_info=True)
            return False
        else:
            return True


class _HTTP2ConnectionContext(object):
    """maintenance a http/2 connection state on specific io_stream
    """
    def __init__(self, io_stream, secure, enable_push,
                 max_buffer_size, initial_window_size):
        self.io_stream = io_stream
        self.schema = 'https' if secure else 'http'
        self.enable_push = enable_push
        self.initial_window_size = initial_window_size
        self.max_buffer_size = max_buffer_size
        self.is_closed = False

        # h2 contexts
        self.stream_delegates = {}
        self.event_handlers = {}  # connection level event, event -> handler
        self.reset_stream_ids = collections.deque(maxlen=50)
        self.h2_conn = h2.connection.H2Connection(client_side=True)
        self.h2_conn.initiate_connection()
        self.h2_conn.update_settings({
            h2.settings.ENABLE_PUSH: int(self.enable_push),
            h2.settings.INITIAL_WINDOW_SIZE: self.initial_window_size,
        })

        self._setup_reading()
        self._flush_to_stream()

    def on_connection_close(self, reason):
        if self.is_closed:
            return

        self.is_closed = True
        for delegate in self.stream_delegates.values():
            delegate.on_connection_close(reason)

    # h2 related
    def _on_connection_streaming(self, data):
        """handles streaming data"""
        if self.is_closed:
            return

        try:
            events = self.h2_conn.receive_data(data)
        except Exception as err:
            try:
                if isinstance(err, h2.exceptions.ProtocolError):
                    self._flush_to_stream()
                self.io_stream.close()
            finally:
                self.on_connection_close(err)
            return

        if events:
            try:
                self._process_events(events)
                self._flush_to_stream()
            except Exception as err:
                try:
                    self.io_stream.close()
                finally:
                    self.on_connection_close(err)

    def _flush_to_stream(self):
        """flush h2 connection data to IOStream"""
        data_to_send = self.h2_conn.data_to_send()
        if data_to_send:
            self.io_stream.write(data_to_send)

    def handle_request(self, request):
        http2_headers = [
            (':authority', request.headers.pop('Host')),
            (':path', request.url),
            (':scheme', self.schema),
            (':method', request.method),
        ] + request.headers.items()

        stream_id = self.h2_conn.get_next_available_stream_id()
        self.h2_conn.send_headers(stream_id, http2_headers, end_stream=not request.body)
        if request.body:
            self.h2_conn.send_data(stream_id, request.body, end_stream=True)

        self._flush_to_stream()
        return stream_id

    def add_stream_delegate(self, stream_id, stream_delegate):
        self.stream_delegates[stream_id] = stream_delegate

    def remove_stream_delegate(self, stream_id):
        del self.stream_delegates[stream_id]

    def add_event_handler(self, event_type, event_handler):
        self.event_handlers[event_type] = event_handler

    def remove_event_handler(self, event_type):
        del self.event_handlers[event_type]

    def reset_stream(self, stream_id, reason=h2.errors.REFUSED_STREAM, flush=False):
        if self.is_closed:
            return

        try:
            self.h2_conn.reset_stream(stream_id, reason)
        except h2.exceptions.StreamClosedError:
            return
        else:
            if flush:
                self._flush_to_stream()

    def _process_events(self, events):
        stream_inbounds = collections.defaultdict(int)

        for event in events:
            if isinstance(event, h2.events.DataReceived):
                stream_inbounds[event.stream_id] += event.flow_controlled_length

            if isinstance(event, h2.events.PushedStreamReceived):
                stream_id = event.parent_stream_id
            else:
                stream_id = getattr(event, 'stream_id', None)

            if stream_id is not None and stream_id != 0:
                if stream_id in self.stream_delegates:
                    stream_delegate = self.stream_delegates[stream_id]

                    with stack_context.ExceptionStackContext(stream_delegate.handle_exception):
                        stream_delegate.handle_event(event)
                else:
                    # FIXME: our nginx server will simply reset stream,
                    # without increase the window size which consumed by
                    # queued data frame which was belongs to the stream we're resetting
                    # self.reset_stream(stream_id)
                    if stream_id in self.reset_stream_ids:
                        if isinstance(event, h2.events.StreamEnded):
                            self.reset_stream_ids.remove(stream_id)
                    else:
                        logger.warning('Unexpected stream: %s, event: %r', stream_id, event)

                continue

            event_type = type(event)
            if event_type in self.event_handlers:
                try:
                    self.event_handlers[event_type](event)
                except Exception as err:
                    logger.exception('Exception while handling event: %r', err)

                continue

            logger.debug('ignored event: %r, %r', event, event.__dict__)

        # collects all inbound lengths, reducing the count of WindowUpdate frames.
        connection_inbound = 0
        for stream_id, stream_inbound in stream_inbounds.items():
            if not stream_inbound:
                continue

            connection_inbound += stream_inbound
            try:
                self.h2_conn.increment_flow_control_window(stream_inbound, stream_id)
            except (h2.exceptions.StreamClosedError, KeyError):
                # we can simply ignore StreamClosedError because closed streams
                # doesn't requires WindowUpdate
                pass

        if connection_inbound:
            self.h2_conn.increment_flow_control_window(connection_inbound)

    def _setup_reading(self, *_):
        if self.is_closed:
            return

        with stack_context.NullContext():
            self.io_stream.read_bytes(
                num_bytes=65535, callback=self._setup_reading,
                streaming_callback=self._on_connection_streaming)


class _HTTP2Stream(object):
    _SUPPORTED_METHODS = set(["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])

    def __init__(
            self, io_loop, context, request, default_host=None,
            release_callback=None, final_callback=None, stream_id=None):
        self.start_time = time.time()
        self.io_loop = io_loop
        self.context = context
        self.release_callback = release_callback
        self.final_callback = final_callback

        self.chunks = []
        self.headers = None
        self.code = None
        self.reason = None

        self._timeout = None
        self._pushed_streams = {}
        self._pushed_responses = {}
        self._stream_ended = False
        self._finalized = False
        self._decompressor = None

        self.request = request
        with stack_context.ExceptionStackContext(self.handle_exception):
            if request.request_timeout:
                self._timeout = self.io_loop.add_timeout(
                    self.start_time + request.request_timeout, self._on_timeout)

            if stream_id is None:
                self.request = self.prepare_request(request, default_host)
                self.stream_id = self.context.handle_request(self.request)
            else:
                self.request = request
                self.stream_id = stream_id

            self.context.add_stream_delegate(self.stream_id, self)

    @classmethod
    def build_http_headers(cls, headers):
        http_headers = httputil.HTTPHeaders()
        for name, value in headers:
            http_headers.add(name, value)

        return http_headers

    def from_push_stream(self, event):
        headers = self.build_http_headers(event.headers)

        method = headers.pop(':method')
        scheme = headers.pop(':scheme')
        authority = headers.pop(':authority')
        path = headers.pop(':path')

        full_url = '%s://%s%s' % (scheme, authority, path)
        request = HTTPRequest(url=full_url, method=method, headers=headers)
        return _HTTP2Stream(
            io_loop=self.io_loop, context=self.context,
            request=request, stream_id=event.pushed_stream_id,
            final_callback=functools.partial(
                self.finish_push_stream, event.pushed_stream_id)
        )

    def finish_push_stream(self, stream_id, response):
        if self._finalized:
            return

        self._pushed_responses[stream_id] = response
        if not self._stream_ended:
            return

        if len(self._pushed_streams) == len(self._pushed_responses):
            self.finish()

    @classmethod
    def prepare_request(cls, request, default_host):
        parsed = urlparse.urlsplit(_unicode(request.url))
        if (request.method not in cls._SUPPORTED_METHODS and
                not request.allow_nonstandard_methods):
            raise KeyError("unknown method %s" % request.method)
        request.follow_redirects = False
        for key in ('network_interface',
                    'proxy_host', 'proxy_port',
                    'proxy_username', 'proxy_password',
                    'expect_100_continue', 'body_producer',
                    ):
            if getattr(request, key, None):
                raise NotImplementedError('%s not supported' % key)

        request.headers.pop('Connection', None)
        if "Host" not in request.headers:
            if not parsed.netloc:
                request.headers['Host'] = default_host
            elif '@' in parsed.netloc:
                request.headers["Host"] = parsed.netloc.rpartition('@')[-1]
            else:
                request.headers["Host"] = parsed.netloc
        username, password = None, None
        if parsed.username is not None:
            username, password = parsed.username, parsed.password
        elif request.auth_username is not None:
            username = request.auth_username
            password = request.auth_password or ''
        if username is not None:
            if request.auth_mode not in (None, "basic"):
                raise ValueError("unsupported auth_mode %s",
                                 request.auth_mode)
            auth = utf8(username) + b":" + utf8(password)
            request.headers["Authorization"] = (
                b"Basic " + base64.b64encode(auth))
        if request.user_agent:
            request.headers["User-Agent"] = request.user_agent
        if not request.allow_nonstandard_methods:
            # Some HTTP methods nearly always have bodies while others
            # almost never do. Fail in this case unless the user has
            # opted out of sanity checks with allow_nonstandard_methods.
            body_expected = request.method in ("POST", "PATCH", "PUT")
            body_present = request.body is not None
            if ((body_expected and not body_present) or
                (body_present and not body_expected)):
                raise ValueError(
                    'Body must %sbe None for method %s (unless '
                    'allow_nonstandard_methods is true)' %
                    ('not ' if body_expected else '', request.method))
        if request.body is not None:
            # When body_producer is used the caller is responsible for
            # setting Content-Length (or else chunked encoding will be used).
            request.headers["Content-Length"] = str(len(
                request.body))
        if (request.method == "POST" and
                "Content-Type" not in request.headers):
            request.headers["Content-Type"] = "application/x-www-form-urlencoded"
        if request.use_gzip:
            request.headers["Accept-Encoding"] = "gzip"

        request.url = (
            (parsed.path or '/') +
            (('?' + parsed.query) if parsed.query else '')
        )
        return request

    def headers_received(self, first_line, headers):
        if self.request.use_gzip \
                and headers.get("Content-Encoding") == "gzip":
            self._decompressor = GzipDecompressor()

            # Downstream delegates will only see uncompressed data,
            # so rename the content-encoding header.
            headers.add("X-Consumed-Content-Encoding",
                        headers["Content-Encoding"])
            del headers["Content-Encoding"]

        self.headers = headers
        self.code = first_line.code
        self.reason = first_line.reason

        if self.request.header_callback is not None:
            # Reassemble the start line.
            self.request.header_callback('%s %s %s\r\n' % first_line)
            for k, v in self.headers.get_all():
                self.request.header_callback("%s: %s\r\n" % (k, v))
            self.request.header_callback('\r\n')

    def _run_callback(self, response):
        if self._finalized:
            return

        if self.release_callback is not None:
            self.release_callback()
        self.io_loop.add_callback(functools.partial(self.final_callback, response))
        self._finalized = True

    def handle_event(self, event):
        if isinstance(event, h2.events.ResponseReceived):
            headers = self.build_http_headers(event.headers)
            status_code = int(headers.pop(':status'))
            start_line = ResponseStartLine(
                'HTTP/2.0', status_code, httplib.responses[status_code]
            )
            self.headers_received(start_line, headers)
        elif isinstance(event, h2.events.DataReceived):
            self.data_received(event.data)
        elif isinstance(event, h2.events.StreamEnded):
            self._stream_ended = True
            self.context.remove_stream_delegate(self.stream_id)
            if len(self._pushed_responses) == len(self._pushed_streams):
                self.finish()
        elif isinstance(event, h2.events.PushedStreamReceived):
            stream = self.from_push_stream(event)
            self._pushed_streams[event.pushed_stream_id] = stream
        else:
            logger.warning('ignored event: %r, %r', event, event.__dict__)

    def finish(self):
        self._remove_timeout()
        self._unregister_unfinished_streams()

        if self._decompressor:
            self._data_received(self._decompressor.flush())

        data = b''.join(self.chunks)
        original_request = getattr(self.request, "original_request",
                                   self.request)
        new_request = None
        if (self.request.follow_redirects and
            self.request.max_redirects > 0 and
                self.code in (301, 302, 303, 307)):
            new_request = copy.copy(self.request)
            new_request.url = urlparse.urljoin(self.request.url,
                                               self.headers["Location"])
            new_request.max_redirects = self.request.max_redirects - 1
            del new_request.headers["Host"]
            # http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html#sec10.3.4
            # Client SHOULD make a GET request after a 303.
            # According to the spec, 302 should be followed by the same
            # method as the original request, but in practice browsers
            # treat 302 the same as 303, and many servers use 302 for
            # compatibility with pre-HTTP/1.1 user agents which don't
            # understand the 303 status.
            if self.code in (302, 303):
                new_request.method = "GET"
                new_request.body = None
                for h in ["Content-Length", "Content-Type",
                          "Content-Encoding", "Transfer-Encoding"]:
                    try:
                        del self.request.headers[h]
                    except KeyError:
                        pass
            new_request.original_request = original_request
        if self.request.streaming_callback:
            buff = io.BytesIO()
        else:
            buff = io.BytesIO(data)  # TODO: don't require one big string?
        response = HTTP2Response(
            original_request, self.code, reason=self.reason,
            headers=self.headers, request_time=time.time() - self.start_time,
            buffer=buff, effective_url=self.request.url,
            pushed_responses=self._pushed_responses.values(),
            new_request=new_request,
        )
        self._run_callback(response)

    def _data_received(self, chunk):
        if self.request.streaming_callback is not None:
            self.request.streaming_callback(chunk)
        else:
            self.chunks.append(chunk)

    def data_received(self, chunk):
        if self._decompressor:
            compressed_data = chunk
            while compressed_data:
                decompressed = self._decompressor.decompress(compressed_data, 0)
                if decompressed:
                    self._data_received(decompressed)

                compressed_data = self._decompressor.unconsumed_tail
        else:
            self._data_received(chunk)

    def handle_exception(self, typ, error, tb):
        if isinstance(error, _RequestTimeout):
            if self._stream_ended:
                self.finish()
                return True
            else:
                error = HTTPError(599, "Timeout")

        self._remove_timeout()
        self._unregister_unfinished_streams()
        if hasattr(self, 'stream_id'):
            self.context.remove_stream_delegate(self.stream_id)

            # FIXME: our nginx server will simply reset stream,
            # without increase the window size which consumed by
            # queued data frame which was belongs to the stream we're resetting
            # self.context.reset_stream(self.stream_id, flush=True)
            self.context.reset_stream_ids.append(self.stream_id)

        response = HTTP2Response(
            self.request, 599, error=error,
            request_time=time.time() - self.start_time,
        )
        self._run_callback(response)
        return True

    def _unregister_unfinished_streams(self):
        for stream_id in self._pushed_streams:
            if stream_id not in self._pushed_responses:
                self.context.remove_stream_delegate(stream_id)

    def _remove_timeout(self):
        if self._timeout is not None:
            self.io_loop.remove_timeout(self._timeout)
            self._timeout = None

    def _on_timeout(self):
        self._timeout = None
        self.connection_timeout = True
        raise _RequestTimeout()

    def on_connection_close(self, reason=None):
        try:
            raise HTTP2ConnectionClosed(reason)
        except Exception:
            self.handle_exception(*sys.exc_info())
