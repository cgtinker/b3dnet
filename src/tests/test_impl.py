import queue
from ..b3dnet.request import *
from ..b3dnet.connection import *
import string
import threading
import logging
import time


def some_func(*args, **kwargs):
    return args, kwargs


def custom_data():
    for i in range(0, 10):
        for j in string.ascii_letters:
            yield i, j


def stage_sample_data(CLIENT_QUEUE, RESTART=False):
    logging.debug("Staging sample data.")

    # register function on server side
    register_func = Request(
        REQUEST.REGISTER,
        'FUNC_ID_NAME',
        some_func
    )
    CLIENT_QUEUE.put(register_func)

    # execute function with custom data
    for i, j in custom_data():
        CLIENT_QUEUE.put(
            Request(
                REQUEST.CALL,
                'FUNC_ID_NAME',
                None,
                i, j,
                j=i
            )
        )

    if RESTART:
        # clear all function in cache, shutdown server
        CLIENT_QUEUE.put(
            Request((REQUEST.RESTART))
        )

    else:
        # clear all function in cache, shutdown server
        CLIENT_QUEUE.put(
            Request((REQUEST.CLEAR_CACHE | REQUEST.SHUTDOWN))
        )


def correct_auth_client(CLIENT_QUEUE, secret, callback, port, RESTART=False):
    logging.debug("Starting client.")
    if callback is not None:
        logging.debug("Wait for server callback.")
        callback.wait()

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
    time.sleep(0.2)
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
    server.connect(timeout=3.0)

    assert server.flag & SERVER.CONNECTED

    logging.debug("Try receiving data")

    # staging received data in SERVER QUEUE
    while server.flag & SERVER.CONNECTED:
        # check if correct at runtime
        request = SERVER_QUEUE.get()
        if request is None:
            continue

        resp = request.execute()
        if resp is not None:
            tar = test_data.pop()
            assert tar == resp
        SERVER_QUEUE.task_done()

    assert (server.flag & SERVER.CONNECTED) == 0
    assert (server.flag & SERVER.ERROR) == 0
    logging.info("server hsould be dead")
    # flushing the queue
    while not SERVER_QUEUE.empty():
        request = SERVER_QUEUE.get()
        resp = request.execute()
        if resp is not None:
            tar = test_data.pop()
            assert tar == resp
        SERVER_QUEUE.task_done()

    logging.info("flush queue")

    assert len(test_data) == 0


def test_correct_auth_connection(port: int = 9002):
    secret = b'SECRET AUTH'
    q = queue.Queue()

    # callback to sync client and server
    callback = threading.Event()
    c = threading.Thread(target=correct_auth_client,
                         args=(q, secret, callback, port, False))
    s = threading.Thread(target=correct_auth_server,
                         args=(secret, callback, port, False))
    c.start()
    s.start()
    q.join()
    c.join()
    s.join()


def test_correct_auth_connection_restart(port: int = 9102):
    secret = b'SECRET AUTH'
    q = queue.Queue()

    # callback to sync client and server
    callback = threading.Event()
    c = threading.Thread(target=correct_auth_client,
                         args=(q, secret, callback, port, True))
    s = threading.Thread(target=correct_auth_server,
                         args=(secret, callback, port, True))
    c.start()
    s.start()
    c.join()
    q.join()
    del q

    # server should restart so just send again
    import time
    time.sleep(1.0)

    q = queue.Queue()
    c = threading.Thread(target=correct_auth_client,
                         args=(q, secret, callback, port, False))
    c.start()
    c.join()
    s.join()


def test_correct_auth_connection_none(port: int = 9352):
    secret = None
    q = queue.Queue()

    # callback to sync client and server
    callback = threading.Event()
    c = threading.Thread(target=correct_auth_client,
                         args=(q, secret, callback, port, False))
    s = threading.Thread(target=correct_auth_server,
                         args=(secret, callback, port, False))
    c.start()
    s.start()
    logging.info("join stuff")
    time.sleep(0.2)
    c.join()
    logging.info("x")
    s.join()
    logging.info("s")
    q.join()
    logging.info("q")


def wrong_auth_server(key: Optional[bytes], callback: threading.Event, port):
    q = queue.Queue()

    server = TCPServer("localhost", port, q, key)

    callback.set()
    server.connect(timeout=1.0)
    assert (server.flag & SERVER.CONNECTED) == 0
    assert server.flag & SERVER.ERROR
    q.join()


def wrong_auth_client(key: Optional[bytes], callback: threading.Event, port):
    q = queue.Queue()
    q.put(Request(
        (REQUEST.CALL | REQUEST.REGISTER),
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


def test_wrong_auth_bytes(port=9422):
    callback = threading.Event()

    c = threading.Thread(
        target=wrong_auth_client, args=(b'hello_world', callback, port)
    )
    s = threading.Thread(
        target=wrong_auth_server, args=(b'good_night', callback, port)
    )
    c.start()
    s.start()
    s.join()
    c.join()


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
        datefmt='%Y-%m-%d:%H:%M:%S', level=logging.DEBUG)
    _main()