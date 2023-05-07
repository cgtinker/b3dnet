# TCP Server Requests

## Contributer nodes

```
python3 -m venv .venv
source .venv/bin/activate

# run tests
pip install pytest
python3 -m pytest

# generate stubs
pip install mypi
stubgen src/b3dnet

# build package
pip install --upgrade build
python3 -m build
```


TCP setup for realime applications on local machines. As code can get executed based on client side requests, this implementation is not considered to be safe. Only receive Request Objects from sources that you trust.<br>

**TCPRequests are build on top of socketserver and multiprocessing with the main goal to remote control blender via TCP.**


## Why not use Pickle?

The goal was, to give the ability to communicate from other languages. <br>
A Request-Object is a json with a python function as string!
```
{
  "flag": 16,
  "idname": "UNIQUE_FUNCTION_ID",
  "func": """def some_fn(*args, **kwargs):\n\tprint("Hello world")""",
  "args": ["args", 21],
  "kwargs": {"hello": "world"}
}
```

## Usage

Setup the threaded TCPServer to receive and execute Request Objects:
```
import queue
q = queue.Queue()

server = TTCPServer(6000, q, b'secret_key')
server.connect(timeout=3.0)

# recv data, handle requests on receive
while server.flag & SERVER_CONNECTED:
    d = q.get(timeout=0.2)
    resp = handle_request(d)
    q.task_done()

# flush the queue and execute remaining requests
while not q.empty():
    resp = handle_request(q.get(timeout=0.2))
    q.task_done()
```

Create requests and stage them in a Queue. Then send them using the TCPClient.<br>
First, lets stage some requests, you may do this at runtime.

```
import queue
q = queue.Queue()

def hello_world(*args, **kwargs):
    print("Method from client which prints!", args, kwargs)

# register function to the cache on server side
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
# or restart the server to wait for the next incoming connection...
# q.put(Request((REQUEST_RESTART | REQUEST_CLEAR_CACHE)))
```

Create a TCPClient to send data from the queue to the server. <br>
The server can also communicate with default multiprocessing Clients.

```
# use the queue with staged data
# or start the Client in a separate thread and just put data in the queue!
client = TCPClient(6000, q, b'secret_key')
client.connect()

# send requests to server
while client.flag & CLIENT_CONNECTED:
    client.send()
    if client.flag & (CLIENT_SHUTDOWN | CLIENT_ERROR):
        client.cancel()
```

## Request Concept

Using a dict to register functions on the Listener side which then can be called from the Client side. <br>
Once a function isn't required anymore, consider to unregister it. <br>
On the server side, functions may be registered when starting the application which can be called directly. <br>
To do so, add functions to the CACHE dict. <br>

Available flags:
```
REQUEST_REGISTATION     # Register a function with an unique idname
REQUEST_CALL            # Call a function using its idname
REQUEST_UNREGISTRATION  # Unregister a function
REQUEST_SHUTDOWN        # Shutdown the server
REQUEST_RESTART         # Restart the server
REQUEST_CLEAR_CACHE     # Clear all cached functions
```

Modules which can be used by default (others may get filtered out). <br>
You can overwrite this on the server side if necessary.

```
'bpy', 'mathutils', 'bvhtree', 'bmesh', 'bpy_types', 'numpy',
'bpy_extras', 'bl_ui', 'bl_operators', 'bl_math', 'bisect', 'math'
```

# License
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

Copyright (C) Denys Hsu - cgtinker, cgtinker.com, hello@cgtinker.com


