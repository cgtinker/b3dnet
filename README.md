# B3DNet - TCP Server Requests


TCP setup for realime applications on local machines. As code can get executed based on client side requests, this implementation is not considered to be safe. Only execute Tasks from sources that you trust.<br>
**Build on top of socketserver and multiprocessing with the main goal to remote control blender via TCP.**


## Why not use Pickle?

The goal was, to give the ability to communicate from other languages. <br>
In a nutshell, Tasks are jsons with a python function as string!<br>
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

Setup the threaded TCPServer to receive and execute tasks:

```
import queue
from b3dnet.connection import TCPServer, SERVER

q = queue.Queue()
server = TCPServer("localhost", 6000, q, b'')
server.connect(timeout=10.0)

# receive tasks
while server.flag & SERVER.CONNECTED:
    try:
        task = q.get(timeout=1.0, block=True)
    except queue.Empty:
        task = None
        break

    if task:
        q.task_done()

# flush queue
while not q.empty():
    task = q.get(timeout=QUEUE_TIMEOUT)
    if task is None:
        break
    task.execute()
    q.task_done()
```

Create and send tasks using a client:

```
import queue
from b3dnet.connection import TCPClient, CLIENT
from b3dnet.request import *
 
# connect the client
client = TCPClient("localhost", 6000, b'secret_key')
client.connect()


# function which should be passed
def hello_world(*args, **kwargs):
    print("Method from client which prints!", args, kwargs)

# register and call function
register_func = Task(
    (TASK.NEW_FN | TASK.CALL_FN), 'HELLO_WORLD_FN', hello_world
)
client.send(register_func)

# call the function using args
for i in range(0, 1000):
    call_data = Task(
        TASK.CALL_FN, 'HELLO_WORLD_FN', None,
        f"args_{i}", kwargs=f"kwargs_{i}")
    client.send(call_data)

# shutdown or restart the server request
client.send(Task((TASK.SHUTDOWN | TASK.CLEAR_CACHE), ))
# client.send(Task((TASK.RESTART)))
```

Lets extend this and expect we restarted the server:

```
# (re)connect the client
client = TCPClient("localhost", 6000, b'secret_key')
client.connect()

# create a list object
req = Task(TASK.NEW_OB, "OBJECT_ID", list)
client.send(req)

def fn_set(*args):
    return [i for i in list(args)]
 
# add args to the list using some fn 
# (fns and objs are in the same cache so naming matters)
args = [1, 2, 4, 3, 9, 6, 21]
req = Task(
    # it's possible to chain multiple tasks
    (TASK.NEW_FN | TASK.CALL_FN | TASK.DEL_FN | TASK.SET_OB), 
    ["FN_SET_ID", "OBJECT_ID"], fn_set,
    *args
)
client.send(req)

# some fn that takes args
def fn_ob_as_arg(*args):
    x = 0
    for arg in args:
        if isinstance(arg, int):
            x += arg
        if isinstance(arg, list):
            x += fn_ob_as_arg(*arg)
    return x

# send object as args (may use multiple objects)
req = Task(
    (TASK.NEW_FN | TASK.CALL_FN | TASK.OB_AS_ARG | TASK.DEL_FN),
    ["FN_SUM_ID", "OBJECT_ID", "OBJECT_ID"],
    fn_ob_as_arg, 10, 10, 10
)
client.send(req)
```


## Task Concept

Using a dict to register functions and objs on the Listener side which then can be called from the Client side. <br>
Once a function or ob isn't required anymore, consider to unregister it. <br>
On the server side, functions may be registered when starting the application which can be called directly. <br>
To do so, add functions to the CACHE dict. <br>
If you do, consider to start the id name with 'PERSISTENT' so they don't get removed on restart or shutdown of the server. 

Available flags:
```
TASK.NEW_FN             # Register a function with an unique idname
TASK.CALL_FN            # Call a function using its idname
TASK.DEL_FN             # Unregister a function

TASK.NEW_OB             # Register an ob
TASK.SET_OB             # Set an ob by a fn call
TASK.DEL_OB             # Unregister an ob
TASK.OB_AS_ARG:         # Use an ob as arg
TASK.OB_AS_KWARG:       # Use an ob with its idname as kwarg

TASK.PASSTHOUGH         # Do nothing (useful when using client on a seperate thread which pull from queue)
TASK.SHUTDOWN           # Shutdown the server and client
TASK.RESTART            # Restart the server and shutdown client

TASK.CLEAR_CACHE        # Clear all cached functions (also persistent ones)
```

Modules which can be used by default (others may get filtered out). <br>
You can overwrite this on the server & client side if necessary.
-> b3dnet.request.MODULES = [...]

```
'bpy', 'mathutils', 'bvhtree', 'bmesh', 'bpy_types', 'numpy',
'bpy_extras', 'bl_ui', 'bl_operators', 'bl_math', 'bisect', 'math'
```

## Developer nodes

Everything is based around the Tasks. <br>
Once started, the server waits for x-seconds for incoming connections and shutsdown if no connection has been established in time. Then the server basically servers forever in a separete thread, shutsdown and restarts if asked to. All Tasks the server receives are staged in a queue which may be accessed from another thread. <br>
The Client is basically just a multiprocessing client which uses Task object. <br>

```
# setup venv
python3 -m venv .venv
source .venv/bin/activate

# install optional requirements
pip install pytest
pip install mypi
pip install --upgrade build

# run tests
python3 -m pytest

# generate stubs if you make major changes
stubgen src/b3dnet

# build package
python3 -m build
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


