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
from typing import Optional, Any, Callable
from io import StringIO
from dataclasses import dataclass

CACHE = dict()


MODULES = [
    'bpy', 'mathutils', 'bvhtree', 'bmesh', 'bpy_types', 'numpy',
    'bpy_extras', 'bl_ui', 'bl_operators', 'bl_math', 'bisect', 'math'
]


@dataclass(frozen=True)
class TASK:
    REGISTER: int = 1 << 0
    CALL: int = 1 << 1
    UNREGISTER: int = 1 << 2
    SHUTDOWN: int = 1 << 10
    RESTART: int = 1 << 11
    CLEAR_CACHE: int = 1 << 31


class Task:
    flag: int
    idname: Optional[str]
    func: Optional[Callable]

    def __init__(self, flag: int, idname: Optional[str] = None, func: Optional[Callable] = None, *args, **kwargs):
        """ Simple object base to be send via the socket.
        Functions targeting blender may be attached and executed on the local server.
        A function can be registered and called using the idname.
        *args and **kwargs get passed to the called function.

        Flags:
            REQUEST.REGISTER
            REQUEST.CALL
            REQUEST.UNREGISTER
            REQUEST.SHUTDOWN
            REQUEST.RESTART
            REQUEST.CLEAR_CACHE

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
        if flag & TASK.REGISTER:
            assert isinstance(func, Callable)

        self.flag = flag
        self.idname = idname
        self.func = func
        self.args = args
        self.kwargs = kwargs

    def execute(self) -> Optional[Any]:
        """ Executes a request depending on it's flag. """
        response = None

        if self.flag & TASK.REGISTER:
            CACHE[self.idname] = self.func

        if self.flag & TASK.CALL:
            response = CACHE[self.idname](*self.args, **self.kwargs)

        if self.flag & TASK.UNREGISTER:
            del CACHE[self.idname]

        if self.flag & TASK.CLEAR_CACHE:
            CACHE.clear()

        return response

    def to_bytes(self) -> bytes:
        """ Convert request to bytes. 
        Conversion depends on flag. """
        d = self.__dict__.copy()
        if self.flag & TASK.REGISTER:
            d['func'] = _func2string(self.func)  # type: ignore
        j = json.dumps(d)
        return j.encode('utf-8')

    @classmethod
    def from_bytes(cls, resp: bytes):
        """ Creates request from bytes. """
        s = resp.decode('utf-8')
        d = json.loads(s)
        return cls(
            d['flag'],
            d['idname'],
            _string2func(d['func']),
            *d['args'],
            **d['kwargs']
        )

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


def _filter_func_str(s: Optional[str]) -> Optional[str]:
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


def _string2func(s: Optional[str]) -> Optional[Callable]:
    """ Convert (filtered) function string to a callable. """
    if s is not None:
        s = _filter_func_str(s)
    if s is None:
        return s
    tree = ast.parse(s)
    name = tree.body[0].name  # type: ignore
    code = compile(tree, '<string>', 'exec')
    scope = {}
    exec(code, scope)
    return scope[name]


def _func2string(func: Callable) -> Optional[str]:
    """ Converts function to string.
    The function has to be in a safed file.
    Calls to modules may get filtered out. """
    s = inspect.getsource(func)
    s = textwrap.dedent(s)
    s = _filter_func_str(s)
    return s
