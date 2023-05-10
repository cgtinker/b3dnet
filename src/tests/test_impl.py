import queue
from ..b3dnet.request import *
from ..b3dnet.connection import *
import string
import threading
import logging
import time
import socket


def some_func(*args, **kwargs):
    return args, kwargs


def custom_data():
    for i in range(0, 10):
        for j in string.ascii_letters:
            yield i, j


def get_port(delay: float = 0.1) -> int:
    time.sleep(delay)
    sock = socket.socket()
    sock.bind(('', 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def stage_sample_data(CLIENT_QUEUE, RESTART=False):
    logging.debug("Staging sample data.")

    # register function on server side
    register_func = Task(
        (TASK.NEW_FN),
        'FUNC_ID_NAME',
        some_func
    )
    CLIENT_QUEUE.put(register_func)

    # execute function with custom data
    for i, j in custom_data():
        CLIENT_QUEUE.put(
            Task(
                (TASK.CALL_FN),
                'FUNC_ID_NAME',
                None,
                i, j,
                j=i
            )
        )

    if RESTART:
        # clear all function in cache, shutdown server
        CLIENT_QUEUE.put(
            Task(TASK.RESTART)
        )

    else:
        # clear all function in cache, shutdown server
        CLIENT_QUEUE.put(
            Task((TASK.CLEAR_CACHE | TASK.SHUTDOWN)),
        )


def correct_auth_client(CLIENT_QUEUE, secret, callback, port, RESTART=False):
    logging.debug("Starting client.")
    if callback is not None:
        logging.debug("Wait for server callback.")
        callback.wait()
        time.sleep(0.1)

    # Stage sample data.
    if RESTART:
        stage_sample_data(CLIENT_QUEUE, RESTART)
    else:
        stage_sample_data(CLIENT_QUEUE)

    # Start client
    logging.debug("Connecting client.")
    client = TCPClient("localhost", port, secret)
    conn = client.connect()
    assert conn
    time.sleep(0.1)
    assert client.flag & CLIENT.CONNECTED

    # Send staged data
    logging.debug("Try sending data to server.")
    while client.flag & CLIENT.CONNECTED:
        try:
            buf = CLIENT_QUEUE.get(timeout=0.1)
        except queue.Empty:
            logging.error("Queue empty.")
            break
        client.send(buf)
        CLIENT_QUEUE.task_done()

        if client.flag & (CLIENT.SHUTDOWN | CLIENT.ERROR):
            logging.error("Shutdown client.")
            break
    assert (client.flag & CLIENT.ERROR) == 0
    assert client.flag & CLIENT.SHUTDOWN
    assert CLIENT_QUEUE.empty()
    client.cancel()


def correct_auth_server(secret, callback, port, RESTART=False):
    # setup the test data for comparison
    test_data = []
    for i, j in custom_data():
        resp = some_func(i, j, j=i)
        test_data.append(resp)

    test_data = test_data[::-1]

    if RESTART:
        test_data = test_data + test_data

    logging.debug("Starting server.")
    SERVER_QUEUE = queue.Queue()

    if callback is not None:
        callback.set()

    # connect server
    server = TCPServer("localhost", port, SERVER_QUEUE,  secret)
    # generous timeout (testing wise) as thread startup may take a while
    server.connect(timeout=7.0)
    assert server.flag & SERVER.CONNECTED

    logging.debug("Try receiving data")

    # staging received data in SERVER QUEUE
    while server.flag & SERVER.CONNECTED:
        # check if correct at runtime
        req = None
        try:
            req = SERVER_QUEUE.get(timeout=0.2)
        except queue.Empty:
            break

        if req is None:
            SERVER_QUEUE.task_done()
            continue

        resp = req.execute()
        if resp is not None:
            tar = test_data.pop()
            assert [tar] == resp
        SERVER_QUEUE.task_done()
    time.sleep(0.2)
    assert (server.flag & (SERVER.CONNECTED | SERVER.ERROR)) == 0

    # flushing the queue
    while not SERVER_QUEUE.empty():
        req = None
        try:
            req = SERVER_QUEUE.get(timeout=0.2)
        except queue.Empty:
            break

        resp = req.execute()
        SERVER_QUEUE.task_done()
        if resp is not None:
            tar = test_data.pop()
            assert [tar] == resp

    logging.info("flush queue")

    assert len(test_data) == 0


def test_correct_auth_connection():
    port = get_port(0.1)
    secret = b'SECRET AUTH'
    q = queue.Queue()

    # callback to sync client and server
    callback = threading.Event()
    s = threading.Thread(target=correct_auth_server,
                         args=(secret, callback, port, False))
    s.start()
    c = threading.Thread(target=correct_auth_client,
                         args=(q, secret, callback, port, False))
    c.start()
    c.join()
    s.join()


def test_correct_auth_connection_restart():
    time.sleep(0.2)
    port = get_port()
    secret = b'SECRET AUTH'
    q = queue.Queue()

    # callback to sync client and server
    callback = threading.Event()
    s = threading.Thread(target=correct_auth_server,
                         args=(secret, callback, port, True))
    s.start()
    c = threading.Thread(target=correct_auth_client,
                         args=(q, secret, callback, port, True))
    c.start()
    c.join()
    q.join()
    del q

    # server should restart so just send again
    q = queue.Queue()
    c = threading.Thread(target=correct_auth_client,
                         args=(q, secret, callback, port, False))
    c.start()
    c.join()
    s.join()


def test_correct_auth_connection_none():
    port = get_port(0.3)
    secret = None
    q = queue.Queue()

    # callback to sync client and server
    callback = threading.Event()
    s = threading.Thread(target=correct_auth_server,
                         args=(secret, callback, port, False))
    s.start()
    c = threading.Thread(target=correct_auth_client,
                         args=(q, secret, callback, port, False))
    c.start()
    c.join()
    s.join()


def wrong_auth_server(key: Optional[bytes], callback: threading.Event, port):
    port = get_port(0.4)
    q = queue.Queue()

    server = TCPServer("localhost", port, q, key)

    callback.set()
    server.connect(timeout=1.0)
    assert (server.flag & SERVER.CONNECTED) == 0
    assert server.flag & SERVER.ERROR


def wrong_auth_client(key: Optional[bytes], callback: threading.Event, port):
    q = queue.Queue()
    q.put(Task(
        (TASK.CALL_FN | TASK.NEW_FN),
        "SOME_FUNC_ID",
        some_func,
        "args", 1
    ))
    callback.wait()
    client = TCPClient("localhost", port,  key)

    client.connect()
    assert (client.flag & CLIENT.CONNECTED) == 0
    while client.flag & CLIENT.CONNECTED:
        try:
            buf = q.get(timeout=0.1)
        except queue.Empty:
            break
        client.send(buf)
        q.task_done()

    assert (client.flag & CLIENT.CONNECTED) == 0
    assert client.flag & CLIENT.SHUTDOWN


def test_wrong_auth_bytes():
    port = get_port(0.5)
    callback = threading.Event()

    s = threading.Thread(
        target=wrong_auth_server, args=(b'good_night', callback, port)
    )
    s.start()
    c = threading.Thread(
        target=wrong_auth_client, args=(b'hello_world', callback, port)
    )
    c.start()
    c.join()
    s.join()


def _main():
    # currently it's not support to have None + b'auth' secrets
    # due to multiprocessings handshake behaviour.
    # None as auth key theirfore has to be set explicitly.
    # Regular implementation my not include 'None' as auth key

    test_correct_auth_connection()
    test_correct_auth_connection_none()
    test_correct_auth_connection_restart()
    test_wrong_auth_bytes()


if __name__ == '__main__':
    logging.basicConfig(
        format='%(asctime)s,%(msecs)03d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',
        datefmt='%Y-%m-%d:%H:%M:%S', level=logging.WARNING)
    _main()
