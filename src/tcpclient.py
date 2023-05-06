
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
import multiprocessing as mp
from multiprocessing.connection import Connection, Client
from typing import Optional
import threading
import queue
from .request import *


class TCPClient:
    authkey: Optional[bytes]
    conn: Connection
    q: queue.Queue
    flag: int

    def __init__(self, port, q: queue.Queue, authkey=None):
        self.host = HOST
        self.port = port
        self.authkey = authkey
        self.thread_running = threading.Event()
        assert isinstance(q, queue.Queue)
        self.q = q
        self.flag = 0

    def connect(self) -> int:
        address = (self.host, self.port)

        try:
            self.conn = Client(address, family=FAMILY, authkey=self.authkey)
        except ConnectionResetError:
            logging.error("Client Connection Error: Reset by peer.")
        except ConnectionRefusedError:
            logging.error("Client Connection Error: Server not running.")
        except mp.AuthenticationError:
            logging.error("Client Authentication Error: Wrong password.")
        except EOFError:
            logging.error("Client Authentication Error: Wrong password.")

        if not hasattr(self, "conn") or (self.conn is None):
            self.flag |= (CLIENT_SHUTDOWN | CLIENT_ERROR)
            return False

        logging.info(f"Client Connected: Start running socket at {address}.")

        self.flag |= CLIENT_CONNECTED
        return True

    def send(self) -> bool:
        # Get data from queue
        if (self.flag & CLIENT_CONNECTED) == 0:
            return False

        try:
            d = self.q.get(block=True, timeout=QUEUE_TIMEOUT)
        except queue.Empty:
            logging.warning("Update failed: Queue empty.")
            self.flag |= CLIENT_SHUTDOWN
            return False

        # Validate data from queue, has to be a Request object.
        if d is None:
            logging.error("Update failed: Empty Queue Entry.")
            self.flag |= (CLIENT_SHUTDOWN | CLIENT_ERROR)
            return False

        elif not isinstance(d, Request):
            logging.error("Update failed: Invalid queued data.")
            self.flag |= (CLIENT_SHUTDOWN | CLIENT_ERROR)
            return False

        elif d.flag & (REQUEST_RESTART | REQUEST_SHUTDOWN):
            self.flag |= CLIENT_SHUTDOWN

        try:
            data = d.to_bytes()
            self.conn.send_bytes(data)
            self.q.task_done()
        except BrokenPipeError:
            logging.warning("Update failed: Broken Pipe.")
            self.flag |= CLIENT_SHUTDOWN
            return False

        return True

    def cancel(self):
        if hasattr(self, "conn"):
            logging.debug("Shutting down client socket...")
            if self.conn is not None:
                self.conn.close()
            del self.conn

        self.flag &= ~CLIENT_CONNECTED

    def __del__(self):
        self.cancel()
        self.flag = 0


def _main():
    def add_sample_data2q(q: queue.Queue):
        # function which should be passed
        def hello_world(*args, **kwargs):
            print("Method from client which prints!", args, kwargs)

        # register function to the cache
        register_func = Request(
            (REQUEST_REGISTATION | REQUEST_CALL), 'HELLO_WORLD_FN', hello_world
        )
        q.put(register_func)

        # call the function using args
        for i in range(0, 1000):
            call_data = Request(
                REQUEST_CALL, 'HELLO_WORLD_FN', None,
                f"args_{i}", kwargs=f"kwargs_{i}")
            q.put(call_data)

        # shutdown the server request
        q.put(Request((REQUEST_SHUTDOWN | REQUEST_CLEAR_CACHE), ))
        # q.put(Request((REQUEST_RESTART | REQUEST_CLEAR_CACHE)))

    logging.basicConfig(
        format='%(asctime)s,%(msecs)03d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',
        datefmt='%Y-%m-%d:%H:%M:%S', level=logging.DEBUG
    )
    q = queue.Queue()
    add_sample_data2q(q)

    client = TCPClient(6000, q, b'secret_key')
    client.connect()

    # send requests to server
    while client.flag & CLIENT_CONNECTED:
        client.send()
        if client.flag & (CLIENT_SHUTDOWN | CLIENT_ERROR):
            client.cancel()


if __name__ == '__main__':
    _main()
