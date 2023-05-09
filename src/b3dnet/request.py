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
import logging
from typing import Optional, Any, Callable, Union, List
from io import StringIO
from dataclasses import dataclass

CACHE = dict()

MODULES = [
    'bpy', 'mathutils', 'bvhtree', 'bmesh', 'bpy_types', 'numpy',
    'bpy_extras', 'bl_ui', 'bl_operators', 'bl_math', 'bisect', 'math'
]


@dataclass(frozen=True)
class TASK:
    NEW_FN: int = 1 << 0  # register a fn
    CALL_FN: int = 1 << 1  # call a fn
    DEL_FN: int = 1 << 2  # unregister a fn

    NEW_OB: int = 1 << 5
    SET_OB: int = 1 << 6
    DEL_OB: int = 1 << 7
    OB_AS_ARG: int = 1 << 8
    OB_AS_KWARG: int = 1 << 9

    SHUTDOWN: int = 1 << 10  # shutdown server
    RESTART: int = 1 << 11  # restart server

    CLEAR_CACHE: int = 1 << 31


def flatten(objs: Union[list, Any]):
    if isinstance(objs, list):
        for name in objs:
            yield name
    else:
        yield objs


class Task:
    flag: int
    idname: Optional[Union[str, List[str]]]
    func: Optional[Callable]
    args: list
    kwargs: dict

    def __init__(self, flag: int, idname: Optional[Union[str, List[str]]] = None, call: Optional[Callable] = None, *args, **kwargs):
        """ Simple object base to be send via the socket.
        Functions targeting blender may be attached and executed on the local server.
        A function can be registered and called using the idname.
        *args and **kwargs get passed to the called function.

        Flags:
            TASK.REGISTER
            TASK.CALL
            TASK.UNREGISTER
            TASK.SHUTDOWN
            TASK.RESTART
            TASK.CLEAR_CACHE

        Import of modules within the function get filtered:
        Available modules:
            'bpy', 'mathutils', 'bvhtree', 'bmesh', 'bpy_types', 'numpy',
            'bpy_extras', 'bl_ui', 'bl_operators', 'bl_math', 'bisect', 'math'


        Example function task:
        def fn(*args, **kwargs):
            print("hello world", args, kwargs)

        some_fn = Task(
            (TASK.REGISTER | TASK.CALL | TASK.UNREGISTER),
            "EXAMPLE_FUNCTION_ID", fn, "args", kwargs=0)
        b = some_fn.to_bytes()
        client.send_bytes(b)
        ...


        Example object task:
        def ob_fn(obj, *args):
            for arg in args:
                obj.append(args)
            return obj

        fn_task = Task(
            (TASK.REGISTER),
            "MODIFY_OBJ_FN", ob_fn
        )
        client.send_bytes(fn_task.to_bytes)

        some_ob = Task(
            (OBJ.CREATE),
            "SOME_OBJECT_ID", list
        )
        client.send_bytes(some_ob.to_bytes)

        modify_ob = Task(
            (TASK.OBJ_AS_ARG | TASK.CALL_FN),
            ["SOME_OBJECT_ID", "MODIFY_OBJ_FN"],
            None, "args"
        )

        """

        self.flag = flag
        self.idname = idname
        self.func = call
        self.args = list(args)
        self.kwargs = kwargs
        self._validate()

    def _validate(self):
        assert isinstance(self.flag, int)
        if isinstance(self.idname, list):
            for tmp in self.idname:
                assert isinstance(tmp, str)

        if self.flag & TASK.NEW_FN:
            assert isinstance(self.func, Callable)

        invalid_combs = [
            (TASK.OB_AS_ARG | TASK.OB_AS_KWARG),
            (TASK.SHUTDOWN | TASK.RESTART),
            (TASK.NEW_OB | TASK.NEW_FN),
        ]
        for comb in invalid_combs:
            assert self.flag & comb != comb

    def pre_tasks(self, rflag):
        if self.func is None:
            return rflag

        # set new fn
        if self.flag & TASK.NEW_FN:
            for name in flatten(self.idname):
                CACHE[name] = self.func
            rflag |= TASK.NEW_FN

        # set new ob
        elif self.flag & TASK.NEW_OB:
            for name in flatten(self.idname):
                CACHE[name] = self.func()
            rflag |= TASK.NEW_OB
        return rflag

    def combine_tasks(self, rflag):
        obkwargs = {}
        obargs = []
        fns = []
        resp = []

        # set references
        for name in flatten(self.idname):
            ob = CACHE.get(name)
            if not ob:
                continue
            if isinstance(ob, Callable):
                fns.append(ob)
            else:
                obargs.append(ob)
                obkwargs[name] = ob

        # extend args
        if self.flag & TASK.OB_AS_ARG:
            for ob in obargs:
                self.args.append(ob)
            rflag |= TASK.OB_AS_ARG

        # extend kwargs
        if self.flag & TASK.OB_AS_KWARG:
            for k, v in obkwargs.items():
                self.kwargs[k] = v
            rflag |= TASK.OB_AS_KWARG

        # set ob by fn (only makes sense if 1 ob + 1 fn)
        if self.flag & (TASK.CALL_FN | TASK.SET_OB) == (TASK.CALL_FN | TASK.SET_OB):
            for fn in fns:
                for ob in obargs:
                    ob = fn(*self.args, **self.kwargs)
            rflag |= (TASK.CALL_FN | TASK.SET_OB)

        # call fns
        elif self.flag & (TASK.CALL_FN):
            for fn in fns:
                val = fn(*self.args, **self.kwargs)
                resp.append(val)
            rflag |= TASK.CALL_FN

        return rflag, resp

    def post_tasks(self, rflag):
        # delete fns
        if self.flag & TASK.DEL_FN:
            for name in flatten(self.idname):
                ob = CACHE.get(name)
                if not ob:
                    continue
                if isinstance(ob, Callable):
                    del CACHE[name]
            rflag |= TASK.DEL_FN

        # delete obs
        if self.flag & TASK.DEL_OB:
            for name in flatten(self.idname):
                ob = CACHE.get(name)
                if not ob:
                    continue
                if not isinstance(ob, Callable):
                    del CACHE[name]
            rflag |= TASK.DEL_OB

        # clear cache
        if self.flag & TASK.CLEAR_CACHE:
            CACHE.clear()
            rflag |= TASK.CLEAR_CACHE

        if self.flag & TASK.SHUTDOWN:
            CACHE.clear()
            rflag |= TASK.SHUTDOWN

        elif self.flag & TASK.RESTART:
            rflag |= TASK.SHUTDOWN
        return rflag

    def execute(self) -> Optional[Any]:
        """ Executes a request depending on it's flag. """
        rflag = 0
        rflag = self.pre_tasks(rflag)
        rflag, resp = self.combine_tasks(rflag)
        rflag = self.post_tasks(rflag)
        if rflag != self.flag:

            logging.error(
                f"Return value of executed tasks"
                f"do not match task. {rflag} != {self.flag}")
        return resp

    def to_bytes(self) -> bytes:
        """ Convert request to bytes.
        Conversion depends on flag. """
        d = self.__dict__.copy()
        if self.flag & (TASK.NEW_FN | TASK.NEW_OB):
            d['func'] = _func2string(self.func)  # type: ignore
        j = json.dumps(d)
        return j.encode('utf-8')

    @ classmethod
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

    @ staticmethod
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
