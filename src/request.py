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
import ast
import sys
import inspect
import textwrap
import json
import struct
import logging
from typing import Optional, Any, Callable
from io import StringIO
import socket
import multiprocessing

CACHE = dict()

HOST = "localhost"
FAMILY = 'AF_INET'
QUEUE_TIMEOUT = 0.5

MODULES = [
    'bpy', 'mathutils', 'bvhtree', 'bmesh', 'bpy_types', 'numpy',
    'bpy_extras', 'bl_ui', 'bl_operators', 'bl_math', 'bisect', 'math'
]

# REQUEST FLAGS
REQUEST_REGISTATION = 1 << 0
REQUEST_CALL = 1 << 1
REQUEST_UNREGISTRATION = 1 << 2
REQUEST_SHUTDOWN = 1 << 10
REQUEST_RESTART = 1 << 11
REQUEST_CLEAR_CACHE = 1 << 31

# SERVER FLAGS
SERVER_CONNECTED = 1 << 0
SERVER_ERROR = 1 << 2
SERVER_SHUTDOWN = 1 << 3
SERVER_RESTART = 1 << 4

# CLIENT FLAGS
CLIENT_CONNECTED = 1 << 0
CLIENT_SHUTDOWN = 1 << 1
CLIENT_ERROR = 1 << 2


class Request:
    flag: int
    idname: Optional[str]
    func: Optional[Callable]

    def __init__(self, flag: int, idname: Optional[str] = None, func: Optional[Callable] = None, *args, **kwargs):
        """ Simple object base to be send via the socket.
        Functions targeting blender may be attached and executed on the local server.
        A function can be registered and called using the idname.
        *args and **kwargs get passed to the called function.

        Flags:
            REGISTER_FUNCTION
            CALL_FUNCTION
            UNREGISTER_FUNCTION

            SHUTDOWN_SERVER
            RESTART_SERVER

            CLEAR_CACHE

        Import of modules within the function get filtered:
        Available modules:
            'bpy', 'mathutils', 'bvhtree', 'bmesh', 'bpy_types', 'numpy',
            'bpy_extras', 'bl_ui', 'bl_operators', 'bl_math', 'bisect', 'math'


        Example:
        def fn(*args, **kwargs):
            print("hello world", args, kwargs)

        ob = Request(
            (REGISTER_FUNCTION | CALL_FUNCTION | UNREGISTER_FUNCTION),
            "EXAMPLE_FUNCTION", fn, "args", kwargs=0)

        b = ob.to_bytes()
        client.send_bytes(b)
        """

        assert isinstance(flag, int)
        if idname is not None:
            assert isinstance(idname, str)
        if flag & REQUEST_REGISTATION:
            assert isinstance(func, Callable)

        self.flag = flag
        self.idname = idname
        self.func = func
        self.args = args
        self.kwargs = kwargs

    def to_bytes(self):
        return request2bytes(self)

    @staticmethod
    def _capture(func, *args, **kwargs) -> list:
        # capture stdout of the func call
        lines = list()
        _stdout = sys.stdout
        _stringio = StringIO()
        sys.stdout = _stringio
        func(*args, **kwargs)
        lines.extend(_stringio.getvalue().splitlines())
        sys.stdout = _stdout
        return lines

    def __eq__(self, other):
        func_eq = False
        if self.func and other.func:
            a = self.func(*self.args, **self.kwargs)
            b = other.func(*other.args, **other.kwargs)
            func_eq = a == b
        elif not self.func and not other.func:
            func_eq = True

        return self.flag == other.flag \
            and self.idname == other.idname \
            and self.args == other.args \
            and self.kwargs == other.kwargs \
            and func_eq == True

    def __str__(self):
        arr = [self.__class__.__name__+': { ']
        for k, v in self.__dict__.items():
            arr.append(str(k)+": ")
            arr.append(str(v))
            arr.append(', ')
        arr[-1] = ' }'

        return "".join(arr)


def handle_request(req: Optional[Request]) -> Optional[Any]:
    response = None
    if not req:
        return response

    if req.flag & REQUEST_REGISTATION:
        CACHE[req.idname] = req.func

    if req.flag & REQUEST_CALL:
        response = CACHE[req.idname](*req.args, **req.kwargs)

    if req.flag & REQUEST_UNREGISTRATION:
        del CACHE[req.idname]

    if req.flag & REQUEST_CLEAR_CACHE:
        CACHE.clear()

    return response


# region pack request object
def filter_func_str(s: Optional[str]) -> Optional[str]:
    """ Remove comments, wrappers and most modules.
    Focus support on tools within blender. """
    # TODO: Improve filtering.
    res = []

    if s is None:
        return None

    s.replace(';', '\n')
    for line in s.splitlines():
        # check first sign
        i = 0
        skip = False
        while i < len(line):
            if line[i].isalnum():
                break
            elif line[i] in ['"', "'", '@', '#']:
                skip = True
                break
            else:
                i += 1

        if skip:
            continue

        # only accept certain modules
        iidx = line.find('import')
        if iidx > 0:
            if "as" in s[iidx+6:]:
                s, *_ = s.split("as")

            mods = line[iidx+6:].split()
            skip = False
            for mod in mods:
                cur = mod.split(".")[0]
                if cur not in MODULES:
                    skip = True
            if skip:
                continue

        res.append(line)
        res.append("\n")

    if len(res) > 0:
        res.pop()

    return "".join(res)


def string2func(s: Optional[str]) -> Optional[Callable]:
    """ Convert (filtered) function string to a callable. """
    if s is not None:
        s = filter_func_str(s)
    if s is None:
        return s
    tree = ast.parse(s)
    name = tree.body[0].name  # type: ignore
    code = compile(tree, '<string>', 'exec')
    scope = {}
    exec(code, scope)
    return scope[name]


def func2string(func: Callable) -> Optional[str]:
    """ Converts function to string.
    The function has to be in a safed file.
    Calls to modules may get filtered out. """
    s = inspect.getsource(func)
    s = textwrap.dedent(s)
    s = filter_func_str(s)
    return s


def request2bytes(req: Request) -> bytes:
    """ Convert request to bytes. 
    Conversion depends on flag. """
    d = req.__dict__.copy()
    if req.flag & REQUEST_REGISTATION:
        d['func'] = func2string(req.func)  # type: ignore
    j = json.dumps(d)
    return j.encode('utf-8')


def bytes2request(resp: bytes) -> Request:
    """ Converts request bytes back to pyobject. """
    s = resp.decode('utf-8')
    d = json.loads(s)
    req = Request(
        d['flag'],
        d['idname'],
        string2func(d['func']),
        *d['args'],
        **d['kwargs']
    )
    return req
# endregion


# region send & receive request object
def format_bytes(buf: bytes) -> Request:
    """ Convert byte data dict with np.arrays.
    Input data has to be a json dict in bytes format. """
    return bytes2request(buf)


def recv(conn: Any, size: int) -> Optional[bytes]:
    """ When switching modules (b.e. to multiprocessing or socket)
    receiving may functions differently b.e. os.read(fp, s). """
    try:
        return conn.recv(size)
    except socket.timeout:
        return None


def get_message_size(conn: Any) -> Optional[int]:
    """ Get message size in Int or LongLong as bytes. """
    buf = recv(conn, 4)
    if buf is None or (len(buf) < 4):
        return None

    size, = struct.unpack("!i", buf)
    if size == -1:
        buf = recv(conn, 8)
        if buf is None or len(buf) < 8:
            return None
        size, = struct.unpack("!Q", buf)

    return size


def recv_bytes(conn: Any, size: int, buffer=b'') -> Optional[bytes]:
    """ Receive data in chunks and returns combined message.
    This receive method requires the correct size of the incomming buffer. """
    remaining = size
    while remaining > 0:
        chunk = recv(conn, remaining)
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


def send_bytes(conn: socket.socket, buf: bytes) -> None:
    """ Based on multiprocessings sending mechanic.
    This does not support messages which don't fit in a generic buffer.
    To send large messages split them into chunks. """
    n = len(buf)
    if n > 0x7fffffff:
        pre_header = struct.pack("!i", -1)
        header = struct.pack("!Q", n)
        conn.send(pre_header)
        conn.send(header)
        conn.send(buf)
    else:
        # For wire compatibility with 3.7 and lower
        header = struct.pack("!i", n)
        if n > 16384:
            conn.send(header)
            conn.send(buf)
        else:
            conn.send(header + buf)


def read(conn: Any) -> Optional[bytes]:
    """ Read data from request handle. """
    size = get_message_size(conn)
    if not size:
        return None

    buf = recv_bytes(conn, size)
    return buf
# endregion

# Handshake protocol based on multiprocessing.
# Extended to refuse None + random bytes connection.
# To provide an easy way to connect multiprocessing clients.
# Licensed to PSF under a Contributor Agreement.


MESSAGE_LENGTH = 20
CHALLENGE = b'#CHALLENGE#'
WELCOME = b'#WELCOME#'
FAILURE = b'#FAILURE#'

# multiprocessing.connection Authentication Handshake Protocol Description
# (as documented for reference after reading the existing code)
# =============================================================================
#      Serving side                           Client side
#     ------------------------------  ---------------------------------------
# 0.                                  Open a connection on the pipe.
# 1.  Accept connection.
# 2.  New random 20 bytes -> MESSAGE
# 3.  send 4 byte length (net order)
#     prefix followed by:
#       b'#CHALLENGE#' + MESSAGE
# 4.                                  Receive 4 bytes, parse as network byte
#                                     order integer. If it is -1, receive an
#                                     additional 8 bytes, parse that as network
#                                     byte order. The result is the length of
#                                     the data that follows -> SIZE.
# 5.                                  Receive min(SIZE, 256) bytes -> M1
# 6.                                  Assert that M1 starts with:
#                                       b'#CHALLENGE#'
# 7.                                  Strip that prefix from M1 into -> M2
# 8.                                  Compute HMAC-MD5 of AUTHKEY, M2 -> C_DIGEST
# 9.                                  Send 4 byte length prefix (net order)
#                                     followed by C_DIGEST bytes.
# 10. Compute HMAC-MD5 of AUTHKEY,
#     MESSAGE into -> M_DIGEST.
# 11. Receive 4 or 4+8 byte length
#     prefix (#4 dance) -> SIZE.
# 12. Receive min(SIZE, 256) -> C_D.
# 13. Compare M_DIGEST == C_D:
# 14a: Match? Send length prefix &
#       b'#WELCOME#'
#    <- RETURN
# 14b: Mismatch? Send len prefix &
#       b'#FAILURE#'
#    <- CLOSE & AuthenticationError
# 15.                                 Receive 4 or 4+8 byte length prefix (net
#                                     order) again as in #4 into -> SIZE.
# 16.                                 Receive min(SIZE, 256) bytes -> M3.
# 17.                                 Compare M3 == b'#WELCOME#':
# 17a.                                Match? <- RETURN
# 17b.                                Mismatch? <- CLOSE & AuthenticationError
#
# If this RETURNed, the connection remains open: it has been authenticated.


def deliver_challenge(conn: socket.socket, authkey: bytes) -> None:
    import hmac
    import os
    logging.debug("Deliver challange...")
    if not isinstance(authkey, bytes):
        raise ValueError(
            "Authkey must be bytes, not {0!s}".format(type(authkey)))
    message = os.urandom(MESSAGE_LENGTH)
    send_bytes(conn, CHALLENGE + message)
    digest = hmac.new(authkey, message, 'md5').digest()
    response = read(conn)
    if response == digest:
        send_bytes(conn, WELCOME)
    else:
        # Dont send failure respone to avoid blocking
        send_bytes(conn, FAILURE)
        raise multiprocessing.AuthenticationError('digest received was wrong')


def answer_challenge(conn: Any, authkey: bytes) -> None:
    import hmac
    logging.debug("Answer challange...")
    if not isinstance(authkey, bytes):
        raise ValueError(
            "Authkey must be bytes, not {0!s}".format(type(authkey)))
    message = read(conn)
    assert message is not None
    assert message[:len(CHALLENGE)] == CHALLENGE, 'message = %r' % message
    message = message[len(CHALLENGE):]
    digest = hmac.new(authkey, message, 'md5').digest()
    send_bytes(conn, digest)
    response = read(conn)
    assert response is not None
    if response != WELCOME:
        raise multiprocessing.AuthenticationError('digest sent was rejected')


if __name__ == '__main__':
    def fn(*args, **kwargs):
        print("hello world my dear", args, kwargs)

    ob = Request(
        (REQUEST_REGISTATION | REQUEST_CALL | REQUEST_UNREGISTRATION),
        "EXAMPLE_FUNCTION", fn, "args", kwargs=0)

    b = request2bytes(ob)
    r = bytes2request(b)

    handle_request(r)
