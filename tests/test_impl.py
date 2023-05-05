import queue
from src import tcpclient, tcpserver
from src.request import *
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
        REQUEST_REGISTATION,
        'FUNC_ID_NAME',
        some_func
    )
    CLIENT_QUEUE.put(register_func)

    # execute function with custom data
    for i, j in custom_data():
        CLIENT_QUEUE.put(
            Request(
                REQUEST_CALL,
                'FUNC_ID_NAME',
                None,
                i, j,
                j=i
            )
        )

    if RESTART:
        # clear all function in cache, shutdown server
        CLIENT_QUEUE.put(
            Request((REQUEST_RESTART))
        )

    else:
        # clear all function in cache, shutdown server
        CLIENT_QUEUE.put(
            Request((REQUEST_CLEAR_CACHE | REQUEST_SHUTDOWN))
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
    client = tcpclient.TCPClient(port, CLIENT_QUEUE, secret)
    conn = client.connect()
    assert conn
    time.sleep(0.2)
    assert client.flag & CLIENT_CONNECTED

    # Send staged data
    logging.debug("Try sending data to server.")
    while client.flag & tcpclient.CLIENT_CONNECTED:
        client.send()
        if client.flag & (tcpclient.CLIENT_SHUTDOWN | tcpclient.CLIENT_ERROR):
            break

    assert (client.flag & CLIENT_ERROR) == 0
    assert client.flag & CLIENT_SHUTDOWN
    assert CLIENT_QUEUE.empty()

    logging.debug("Stop client.")
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
    server = tcpserver.TTCPServer(port, SERVER_QUEUE, secret)
    server.connect(timeout=3.0)

    assert server.flag & SERVER_CONNECTED

    logging.debug("Try receiving data")

    # staging received data in SERVER QUEUE
    while server.flag & SERVER_CONNECTED:
        # check if correct at runtime
        request = SERVER_QUEUE.get()
        if request is None:
            continue

        resp = handle_request(request)
        if resp is not None:
            tar = test_data.pop()
            assert tar == resp
        SERVER_QUEUE.task_done()

    assert (server.flag & SERVER_CONNECTED) == 0
    assert (server.flag & SERVER_ERROR) == 0

    # flushing the queue
    while not SERVER_QUEUE.empty():
        request = SERVER_QUEUE.get()
        resp = handle_request(request)
        if resp is not None:
            tar = test_data.pop()
            assert tar == resp
        SERVER_QUEUE.task_done()

    assert len(test_data) == 0


def test_correct_auth_connection(port: int = 9000):
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


def test_correct_auth_connection_restart(port: int = 9001):
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


def test_correct_auth_connection_none(port: int = 9008):
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
    time.sleep(0.2)
    q.join()
    c.join()
    s.join()


def wrong_auth_server(key: Optional[bytes], callback: threading.Event, port):
    q = queue.Queue()

    server = tcpserver.TTCPServer(port, q, key)

    callback.set()
    server.connect(timeout=1.0)
    assert (server.flag & SERVER_CONNECTED) == 0
    assert server.flag & SERVER_ERROR
    q.join()


def wrong_auth_client(key: Optional[bytes], callback: threading.Event, port):
    q = queue.Queue()
    q.put(Request(
        (REQUEST_CALL | REQUEST_REGISTATION),
        "SOME_FUNC_ID",
        some_func,
        "args", 1
    ))
    callback.wait()
    client = tcpclient.TCPClient(port, q, key)
    client.connect()

    if client.flag & CLIENT_CONNECTED:
        logging.error("Client sending.")
        client.send()

    assert (client.flag & CLIENT_CONNECTED) == 0
    assert client.flag & CLIENT_SHUTDOWN


def test_wrong_auth_bytes(port=9003):
    callback = threading.Event()

    c = threading.Thread(
        target=wrong_auth_client, args=(b'hello_world', callback, port)
    )
    s = threading.Thread(
        target=wrong_auth_server, args=(b'good_night', callback, port)
    )
    c.start()
    s.start()


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
