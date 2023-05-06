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

import multiprocessing
import socketserver
import threading
import queue
import logging
from typing import Optional
from src.request import *


class TTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    def __init__(self, port: int, q: queue.Queue, auth: Optional[bytes] = None):
        super().__init__((HOST, port), TCPServerHandler)
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

        # do multiprocessings challange / handshake
        if self.auth is not None:
            assert isinstance(self.auth, bytes)

            try:
                deliver_challenge(c, self.auth)
                answer_challenge(c, self.auth)
                logging.info("Connection established.")

            except AssertionError:
                logging.error("Server Authentication Error: Wrong password.")
                self.flag |= SERVER_ERROR
                self.running.clear()
            except multiprocessing.AuthenticationError:
                logging.error("Server Authentication Error: Wrong password.")
                self.flag |= SERVER_ERROR
                self.running.clear()

        if (self.flag & SERVER_ERROR) == 0:
            self.flag = SERVER_CONNECTED
            self.running.set()
        return (c, address)


class TCPServerHandler(socketserver.StreamRequestHandler):
    server: TTCPServer

    def handle(self):
        logging.info(
            f"Run threaded TCPServer: {self.server.running.is_set()} {self.server.flag & SERVER_CONNECTED}")
        self.req = None

        while self.server.flag & SERVER_CONNECTED:
            b: Optional[bytes] = read(self.request)

            if b is None:
                logging.warning("Reading operation timed out, shut down.")
                self.server.running.clear()
                break

            self.req = format_bytes(b)
            self.server.queue.put(self.req)
            if self.req.flag & (REQUEST_RESTART | REQUEST_SHUTDOWN):
                logging.debug("Received server control request...")
                break

            if self.server.flag & SERVER_ERROR:
                logging.error("Error occured.")
                break

    def finish(self):
        """ Shutdown server if data is missing or when
        flag for restart / shutdown has been received. """
        if not self.server.running.is_set() or self.req is None:
            logging.debug(
                f"Server active: {self.server.running.is_set()}, Request: {self.req}")
            pass
        elif self.req.flag & REQUEST_SHUTDOWN:
            logging.debug("Server shutdown...")
            pass
        elif self.server.flag & SERVER_ERROR:
            logging.debug("Server error...")
            pass
        elif self.req.flag & REQUEST_RESTART:
            self.server.flag |= SERVER_RESTART
            logging.debug("Server restart...")
            return
        else:
            logging.warning("Server shutdown reason unknown.")

        self.server.flag &= ~SERVER_CONNECTED
        self.server.running.clear()
        self.server.shutdown()
        logging.info("Shutting down.")


def _main():
    logging.basicConfig(
        format='%(asctime)s,%(msecs)03d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',
        datefmt='%Y-%m-%d:%H:%M:%S', level=logging.DEBUG
    )

    q = queue.Queue()
    server = TTCPServer(6000, q, b'secret_key')
    server.connect(timeout=10.0)

    # recv sync
    while server.flag & SERVER_CONNECTED:
        d = q.get(timeout=0.2)
        resp = handle_request(d)
        q.task_done()

    # flush queue
    while not q.empty():
        resp = handle_request(q.get(timeout=0.2))
        q.task_done()


if __name__ == '__main__':
    _main()
