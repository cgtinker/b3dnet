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

import time
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
CONN_TIMEOUT = 15.0
SOCK_TIMEOUT = 3.0
QUEUE_TIMEOUT = 3.0


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
    def __init__(self, host: str, port: int, q: queue.Queue, auth: Optional[bytes] = None):
        super().__init__((host, port), TCPServerHandler)
        if auth is not None:
            assert isinstance(auth, bytes)

        self.running = threading.Event()
        self.auth = auth
        self.queue = q
        self.flag = 0

    def connect(self, timeout: float = CONN_TIMEOUT):
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
            c.settimeout(SOCK_TIMEOUT)

        # do multiprocessings challenge / handshake
        fake_mp_conn = SocketWrapper(c)
        if self.auth is not None:
            assert isinstance(self.auth, bytes)

            try:
                logging.info("Deliver challange.")
                mpc.deliver_challenge(fake_mp_conn, self.auth)
                logging.info("Deliver answer.")
                mpc.answer_challenge(fake_mp_conn, self.auth)
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
    """ Wrapping to use multiprocessing handshake. """

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
            f"Run threaded TCPServer: {self.server.running.is_set() == self.server.flag & SERVER.CONNECTED == 1}")
        self.req = None

        while self.server.flag & SERVER.CONNECTED:
            b: Optional[bytes] = recv_bytes(self.request)
            if b is None:
                if self.server.flag & (SERVER.ERROR | SERVER.SHUTDOWN | SERVER.RESTART):
                    logging.info(f"Shutting down because {self.server.flag}")
                    break

                # self.server.running.clear()
                if not self.server.running.is_set():
                    logging.info("self running not set")
                    break

                time.sleep(0.5)
                continue

            self.req = Task.from_bytes(b)
            self.server.queue.put(self.req)
            if self.req.flag & (TASK.RESTART | TASK.SHUTDOWN):
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
                f"Server active: {self.server.running.is_set()}")
            pass
        elif self.req.flag & TASK.SHUTDOWN:
            logging.debug("Server shutdown...")
            pass
        elif self.server.flag & SERVER.ERROR:
            logging.debug("Server error...")
            pass
        elif self.req.flag & TASK.RESTART:
            self.server.flag |= SERVER.RESTART
            logging.debug("Server restart...")
            return
        else:
            logging.warning("Server shutdown reason unknown.")

        self.server.flag &= ~SERVER.CONNECTED
        self.server.running.clear()
        self.server.shutdown()
        logging.info("Server shutting down 2.")
        super().finish()
        logging.info("Server shutting down.")


class TCPClient:
    authkey: Optional[bytes]
    conn: mpc.Connection
    q: queue.Queue
    flag: int

    def __init__(self,  host: str, port: int, authkey=None):
        self.host = host
        self.port = port
        self.authkey = authkey
        self.thread_running = threading.Event()
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

    def send(self, buf: Optional[Task]) -> bool:
        # maybe thats better?
        # Get data from queue
        if (self.flag & CLIENT.CONNECTED) == 0:
            raise ConnectionError

        # Validate data from queue, has to be a Request object.
        if buf is None:
            logging.error("Update failed: Empty Queue Entry.")
            self.flag |= (CLIENT.SHUTDOWN | CLIENT.ERROR)
            return False

        elif not isinstance(buf, Task):
            logging.error("Update failed: Invalid queued data.")
            self.flag |= (CLIENT.SHUTDOWN | CLIENT.ERROR)
            return False

        elif buf.flag & (TASK.RESTART | TASK.SHUTDOWN):
            self.flag |= CLIENT.SHUTDOWN

        try:
            data = buf.to_bytes()
            self.conn.send_bytes(data)
        except BrokenPipeError:
            logging.warning("Update failed: Broken Pipe.")
            self.flag |= CLIENT.SHUTDOWN
            self.cancel()
            return False

        return True

    def cancel(self):
        if hasattr(self, "conn"):
            logging.debug("Shutting down client socket...")
            if self.conn is not None:
                self.conn.close()
            del self.conn

        if hasattr(self, "flag"):
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
    except ConnectionResetError:
        logging.error("Connection Reset Error Occured.")
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
        register_func = Task(
            (TASK.NEW_FN | TASK.CALL_FN), 'HELLO_WORLD_FN', hello_world
        )
        q.put(register_func)

        # call the function using args
        for i in range(0, 1000):
            call_data = Task(
                TASK.CALL_FN, 'HELLO_WORLD_FN', None,
                f"args_{i}", kwargs=f"kwargs_{i}")
            q.put(call_data)

        # shutdown the server request
        q.put(Task((TASK.SHUTDOWN | TASK.CLEAR_CACHE), ))
        # q.put(Task((TASK.RESTART | TASK.CLEAR_CACHE)))

    logging.basicConfig(
        format='%(asctime)s,%(msecs)03d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',
        datefmt='%Y-%m-%d:%H:%M:%S', level=logging.DEBUG
    )
    q = queue.Queue()
    add_sample_data2q(q)

    client = TCPClient("localhost", 6000, b'secret_key')
    client.connect()

    # send requests to server
    while client.flag & CLIENT.CONNECTED:
        try:
            buf = q.get(timeout=0.2)
        except queue.Empty:
            break
        client.send(buf)
    client.cancel()


def _example_server():
    logging.basicConfig(
        format='%(asctime)s,%(msecs)03d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',
        datefmt='%Y-%m-%d:%H:%M:%S', level=logging.DEBUG
    )

    q = queue.Queue()
    logging.info("Wait for connection...")
    server = TCPServer("localhost", 6000, q, b'')
    server.connect(timeout=10.0)

    # recv sync
    logging.info("Receive tasks")
    while server.flag & SERVER.CONNECTED:
        try:
            # wait time for new incoming conenctions
            task = q.get(timeout=20, block=True)
        except queue.Empty:
            task = None
            break

        if task:
            q.task_done()

    # flush queue
    while not q.empty():
        req = q.get(timeout=QUEUE_TIMEOUT)
        # if req:
        # req.execute()

        q.task_done()


if __name__ == '__main__':
    _example_server()
