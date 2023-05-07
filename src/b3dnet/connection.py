'''
Copyright (C) cgtinker, cgtinker.com, hello@cgtinker.com

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

import logging
import socketserver
import multiprocessing as mp
from multiprocessing import connection as mpc
from typing import Optional
import threading
import queue
import socket
import struct
from .request import *


FAMILY = 'AF_INET'
QUEUE_TIMEOUT = 0.5


@dataclass(frozen=True)
class SERVER:
    CONNECTED: int = 1 << 0
    ERROR: int = 1 << 2
    SHUTDOWN: int = 1 << 3
    RESTART: int = 1 << 4


@dataclass(frozen=True)
class CLIENT:
    CONNECTED: int = 1 << 0
    SHUTDOWN: int = 1 << 1
    ERROR: int = 1 << 2


class TCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    def __init__(self, port: int, q: queue.Queue, host: str = "localhost", auth: Optional[bytes] = None):
        super().__init__((host, port), TCPServerHandler)
        if auth is not None:
            assert isinstance(auth, bytes)

        self.running = threading.Event()
        self.auth = auth
        self.queue = q
        self.flag = 0

    def connect(self, timeout: float = 3.0):
        server_thread = threading.Thread(target=self.serve_forever)
        server_thread.daemon = True
        server_thread.start()
        self.running.wait(timeout)

    def get_request(self):
        """ Deliver multiprocessings password challange. """
        if self.socket is None:
            raise OSError("Server socket is closed.")

        # accept connection
        c, address = self.socket.accept()
        if c.gettimeout() is None:
            c.settimeout(3.0)

        # do multiprocessings challenge / handshake
        fakemp = SocketWrapper(c)
        if self.auth is not None:
            assert isinstance(self.auth, bytes)

            try:
                mpc.deliver_challenge(fakemp, self.auth)
                mpc.answer_challenge(fakemp, self.auth)
                logging.info("Connection established.")

            except AssertionError:
                logging.error("Server Authentication Error: Wrong password.")
                self.flag |= SERVER.ERROR
                self.running.clear()
            except mp.AuthenticationError:
                logging.error("Server Authentication Error: Wrong password.")
                self.flag |= SERVER.ERROR
                self.running.clear()

        if (self.flag & SERVER.ERROR) == 0:
            self.flag = SERVER.CONNECTED
            self.running.set()
        return (c, address)


class SocketWrapper(mpc.Connection):
    """ Wrapper to use multiprocessing handshake. """

    def __init__(self, sock: socket.socket):
        self.sock = sock

    def recv_bytes(self, *_):
        return recv_bytes(self.sock)

    def send_bytes(self, buf):
        send_bytes(self.sock, buf)


class TCPServerHandler(socketserver.StreamRequestHandler):
    server: TCPServer

    def handle(self):
        logging.info(
            f"Run threaded TCPServer: {self.server.running.is_set()} {self.server.flag & SERVER.CONNECTED}")
        self.req = None

        while self.server.flag & SERVER.CONNECTED:
            b: Optional[bytes] = recv_bytes(self.request)

            if b is None:
                logging.warning("Reading operation timed out, shut down.")
                self.server.running.clear()
                break

            self.req = Request.from_bytes(b)
            self.server.queue.put(self.req)
            if self.req.flag & (REQUEST.RESTART | REQUEST.SHUTDOWN):
                logging.debug("Received server control request...")
                break

            if self.server.flag & SERVER.ERROR:
                logging.error("Error occured.")
                break

    def finish(self):
        """ Shutdown server if data is missing or when
        flag for restart / shutdown has been received. """
        if not self.server.running.is_set() or self.req is None:
            logging.debug(
                f"Server active: {self.server.running.is_set()}, Request: {self.req}")
            pass
        elif self.req.flag & REQUEST.SHUTDOWN:
            logging.debug("Server shutdown...")
            pass
        elif self.server.flag & SERVER.ERROR:
            logging.debug("Server error...")
            pass
        elif self.req.flag & REQUEST.RESTART:
            self.server.flag |= SERVER.RESTART
            logging.debug("Server restart...")
            return
        else:
            logging.warning("Server shutdown reason unknown.")

        self.server.flag &= ~SERVER.CONNECTED
        self.server.running.clear()
        self.server.shutdown()
        logging.info("Shutting down.")


class TCPClient:
    authkey: Optional[bytes]
    conn: mpc.Connection
    q: queue.Queue
    flag: int

    def __init__(self, port, q: queue.Queue, host: str = "localhost", authkey=None):
        self.host = host
        self.port = port
        self.authkey = authkey
        self.thread_running = threading.Event()
        assert isinstance(q, queue.Queue)
        self.q = q
        self.flag = 0

    def connect(self) -> int:
        address = (self.host, self.port)

        try:
            self.conn = mpc.Client(
                address, family=FAMILY, authkey=self.authkey
            )
        except ConnectionResetError:
            logging.error("Client Connection Error: Reset by peer.")
        except ConnectionRefusedError:
            logging.error("Client Connection Error: Server not running.")
        except mp.AuthenticationError:
            logging.error("Client Authentication Error: Wrong password.")
        except EOFError:
            logging.error("Client Authentication Error: Wrong password.")

        if not hasattr(self, "conn") or (self.conn is None):
            self.flag |= (CLIENT.SHUTDOWN | CLIENT.ERROR)
            return False

        logging.info(f"Client Connected: Start running socket at {address}.")

        self.flag |= CLIENT.CONNECTED
        return True

    def send(self) -> bool:
        # Get data from queue
        if (self.flag & CLIENT.CONNECTED) == 0:
            return False

        try:
            d = self.q.get(block=True, timeout=QUEUE_TIMEOUT)
        except queue.Empty:
            logging.warning("Update failed: Queue empty.")
            self.flag |= CLIENT.SHUTDOWN
            return False

        # Validate data from queue, has to be a Request object.
        if d is None:
            logging.error("Update failed: Empty Queue Entry.")
            self.flag |= (CLIENT.SHUTDOWN | CLIENT.ERROR)
            return False

        elif not isinstance(d, Request):
            logging.error("Update failed: Invalid queued data.")
            self.flag |= (CLIENT.SHUTDOWN | CLIENT.ERROR)
            return False

        elif d.flag & (REQUEST.RESTART | REQUEST.SHUTDOWN):
            self.flag |= CLIENT.SHUTDOWN

        try:
            data = d.to_bytes()
            self.conn.send_bytes(data)
            self.q.task_done()
        except BrokenPipeError:
            logging.warning("Update failed: Broken Pipe.")
            self.flag |= CLIENT.SHUTDOWN
            return False

        return True

    def cancel(self):
        if hasattr(self, "conn"):
            logging.debug("Shutting down client socket...")
            if self.conn is not None:
                self.conn.close()
            del self.conn

        self.flag &= ~CLIENT.CONNECTED

    def __del__(self):
        self.cancel()
        self.flag = 0


# region send & receive
def _send_in_chunks(conn: socket.socket, buf: bytes) -> None:
    """ Send data in chunks if buf size exceeds. """
    N = len(buf)
    while N > 0:
        chunksize = conn.send(buf)
        N -= chunksize
        buf = buf[chunksize:]


def send_bytes(conn: socket.socket, buf: bytes) -> None:
    """ Headers based on multiprocessing to allow 
    usage of multiprocessing clients."""

    n = len(buf)
    if n > 0x7fffffff:
        pre_header = struct.pack("!i", -1)
        header = struct.pack("!Q", n)
        conn.send(pre_header)
        _send_in_chunks(conn, header)
        _send_in_chunks(conn, buf)
    else:
        # For wire compatibility with 3.7 and lower
        header = struct.pack("!i", n)
        if n > 16384:
            _send_in_chunks(conn, header)
            _send_in_chunks(conn, buf)
        else:
            n = conn.send(header + buf)


def _get_message_size(conn: Any) -> Optional[int]:
    """ Get message size in Int or LongLong as bytes. """
    buf = _recv(conn, 4)
    if buf is None or (len(buf) < 4):
        return None

    size, = struct.unpack("!i", buf)
    if size == -1:
        buf = _recv(conn, 8)
        if buf is None or len(buf) < 8:
            return None
        size, = struct.unpack("!Q", buf)

    return size


def _recv(conn: Any, size: int) -> Optional[bytes]:
    """ When switching modules (b.e. to multiprocessing or socket)
    receiving may functions differently b.e. os.read(fp, s). """
    try:
        return conn.recv(size)
    except socket.timeout:
        return None


def _recv_in_chunks(conn: Any, size: int, buffer=b'') -> Optional[bytes]:
    """ Receive data in chunks and returns combined message.
    This receive method requires the correct size of the incomming buffer. """
    remaining = size
    while remaining > 0:
        chunk = _recv(conn, remaining)
        if chunk is None:
            return None

        n = len(chunk)
        if n == 0:
            if remaining == size:
                raise EOFError
            else:
                raise OSError("got end of file during message")
        buffer += chunk
        remaining -= n

    return buffer


def recv_bytes(conn: Any) -> Optional[bytes]:
    """ Read data from request handle. """
    size = _get_message_size(conn)
    if not size:
        return None

    buf = _recv_in_chunks(conn, size)
    return buf
# endregion


def _example_client():
    def add_sample_data2q(q: queue.Queue):
        # function which should be passed
        def hello_world(*args, **kwargs):
            print("Method from client which prints!", args, kwargs)

        # register function to the cache
        register_func = Request(
            (REQUEST.REGISTER | REQUEST.CALL), 'HELLO_WORLD_FN', hello_world
        )
        q.put(register_func)

        # call the function using args
        for i in range(0, 1000):
            call_data = Request(
                REQUEST.CALL, 'HELLO_WORLD_FN', None,
                f"args_{i}", kwargs=f"kwargs_{i}")
            q.put(call_data)

        # shutdown the server request
        q.put(Request((REQUEST.SHUTDOWN | REQUEST.CLEAR_CACHE), ))
        # q.put(Request((REQUEST_RESTART | REQUEST_CLEAR_CACHE)))

    logging.basicConfig(
        format='%(asctime)s,%(msecs)03d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',
        datefmt='%Y-%m-%d:%H:%M:%S', level=logging.DEBUG
    )
    q = queue.Queue()
    add_sample_data2q(q)

    client = TCPClient(6000, q, "localhost", b'secret_key')
    client.connect()

    # send requests to server
    while client.flag & CLIENT.CONNECTED:
        client.send()
        if client.flag & (CLIENT.SHUTDOWN | CLIENT.ERROR):
            client.cancel()


def _example_server():
    logging.basicConfig(
        format='%(asctime)s,%(msecs)03d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',
        datefmt='%Y-%m-%d:%H:%M:%S', level=logging.DEBUG
    )

    q = queue.Queue()
    server = TCPServer(6000, q, "localhost", b'secret_key')
    server.connect(timeout=10.0)

    # recv sync
    while server.flag & SERVER.CONNECTED:
        req = q.get(timeout=0.2)
        if req:
            req.execute()
        q.task_done()

    # flush queue
    while not q.empty():
        req = q.get(timeout=0.2)
        if req:
            req.execute()

        q.task_done()
