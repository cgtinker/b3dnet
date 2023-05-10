from ..b3dnet.request import *
from ..b3dnet import request as req


def test_serialization():
    def fn(*args, **kwargs):
        # some weird nested func for testing
        def add(tar, val):
            if isinstance(val, int):
                tar += val
            elif isinstance(val, float):
                tar += val
        res = 0
        for v in kwargs.items():
            add(res, v)
            for a in args:
                add(res, a)
        return res

    # equality checks returned value as the rebuild
    # function doesn't point at the same function.
    ob = Task(
        (TASK.NEW_FN | TASK.CALL_FN | TASK.DEL_FN),
        "EXAMPLE_FUNCTION", fn, 1, 2, 3, 4, 5, a=2, b=12, d=3)

    b = ob.to_bytes()
    r = Task.from_bytes(b)
    assert r == ob
    req = Task(TASK.CLEAR_CACHE)
    req.execute()


def test_filter_func():
    fns = """def fn(*args, **kwargs):
    import os
    import shutil
    import numpy as np
    import bpy
    import bmesh
    import cv2
    import mediapipe
    __import__(random)
    # some weird nested func for testing
    def add(tar, val):
        if isinstance(val, int):
            tar += val
        elif isinstance(val, float):
            tar += val
    # another comment
    res = 0
    for v in kwargs.items():
        add(res, v)
        for a in args:
            add(res, a)
    return res"""
    res = req._filter_func_str(fns)
    s = """def fn(*args, **kwargs):
    import bpy
    import bmesh
    def add(tar, val):
        if isinstance(val, int):
            tar += val
        elif isinstance(val, float):
            tar += val
    res = 0
    for v in kwargs.items():
        add(res, v)
        for a in args:
            add(res, a)
    return res"""
    assert res == s


def test_func2string():
    def fn(*args, **kwargs):
        import os
        import shutil
        # some weird nested func for testing

        def add(tar, val):
            if isinstance(val, int):
                tar += val
            elif isinstance(val, float):
                tar += val
        # another comment
        res = 0
        for v in kwargs.items():
            add(res, v)
            for a in args:
                add(res, a)
        return res
    s = req._func2string(fn)
    comp = """def fn(*args, **kwargs):

    def add(tar, val):
        if isinstance(val, int):
            tar += val
        elif isinstance(val, float):
            tar += val
    res = 0
    for v in kwargs.items():
        add(res, v)
        for a in args:
            add(res, a)
    return res"""
    assert comp == s


def test_string2func():
    def fn(*args, **kwargs):
        def add(tar, val):
            if isinstance(val, int):
                tar += val
            elif isinstance(val, float):
                tar += val
        res = 0
        for v in kwargs.items():
            add(res, v)
            for a in args:
                add(res, a)
        return res
    comp = """def fn(*args, **kwargs):

    def add(tar, val):
        if isinstance(val, int):
            tar += val
        elif isinstance(val, float):
            tar += val
    res = 0
    for v in kwargs.items():
        add(res, v)
        for a in args:
            add(res, a)
    return res"""
    comp_fn = req._string2func(comp)
    assert comp_fn is not None
    assert fn(1, 2, 3, a=3, b=1) == comp_fn(1, 2, 3, a=3, b=1)


def test_request_registration():
    def fn(*args):
        return args
    req = Task(
        TASK.NEW_FN,
        "SOME_ID",
        fn,
        1, 2, 3)
    req.execute()
    assert CACHE["SOME_ID"] == fn

    req = Task(
        TASK.DEL_FN,
        "SOME_ID")
    req.execute()
    assert "SOME_ID" not in CACHE
    req = Task(TASK.CLEAR_CACHE)
    req.execute()


def test_request_call():
    def fn(*args):
        return args

    req = Task(
        (TASK.NEW_FN | TASK.CALL_FN),
        "SOME_ID",
        fn,
        1, 2, 3)
    resp = req.execute()
    assert resp == [fn(1, 2, 3)]
    req = Task(
        TASK.CALL_FN,
        "SOME_ID",
        None,
        1, 2, 3)
    resp = req.execute()
    assert resp == [fn(1, 2, 3)]

    req = Task(TASK.CLEAR_CACHE)
    req.execute()


def test_request_call_fnames():
    def fn(*args, hello, world):
        return sum(args) + hello + world

    req = Task(
        (TASK.NEW_FN | TASK.CALL_FN),
        "SOME_ID",
        fn,
        1, 2, 3, hello=21, world=32)
    resp = req.execute()
    assert resp == [fn(1, 2, 3, hello=21, world=32)]
    req = Task(
        TASK.CALL_FN,
        "SOME_ID",
        None,
        1, 2, 3, hello=21, world=32)
    resp = req.execute()
    assert resp == [fn(1, 2, 3, hello=21, world=32)]
    req = Task(TASK.CLEAR_CACHE)
    resp = req.execute()


def test_clear_cache():
    req = Task(TASK.CLEAR_CACHE)
    req.execute()

    def fn(*args):
        return args
    req = Task(
        (TASK.NEW_FN | TASK.DEL_FN), "_SOME_ID1", fn)

    req.execute()
    req = Task(TASK.NEW_FN, "_SOME_ID2", fn)
    req.execute()
    req = Task(TASK.NEW_FN, "_SOME_ID3", fn)
    req.execute()
    req = Task(TASK.NEW_FN, "_SOME_ID4", fn)
    req.execute()
    req = Task(TASK.NEW_FN, "_SOME_ID5", fn)
    req.execute()

    assert len(CACHE) == 4
    req = Task(TASK.CLEAR_CACHE)
    req.execute()
    assert len(CACHE) == 0
    req = Task(TASK.CLEAR_CACHE)
    req.execute()


def test_obj_assignment(clear_cache=True):
    # args / kwargs wont get used but should cause issues
    req = Task(TASK.NEW_OB, "OBJECT_ID", list, "random", "args", kwargs="")
    req.execute()
    assert len(CACHE) == 1

    def fn_set(*args):
        return [i for i in list(args)]

    # dont overwrite cache
    args = [1, 2, 4, 3, 9, 6, 21]
    req = Task(
        (TASK.NEW_FN | TASK.CALL_FN | TASK.DEL_FN | TASK.SET_OB),
        ["FN_SET_ID", "OBJECT_ID"], fn_set,
        *args
    )
    req.execute()
    assert CACHE['OBJECT_ID'] == args
    assert len(CACHE) == 1
    if clear_cache:
        req = Task(TASK.CLEAR_CACHE)
        req.execute()


def test_ob_as_arg():
    test_obj_assignment(False)
    assert len(CACHE) == 1
    args = [1, 2, 4, 3, 9, 6, 21]

    def fn_ob_as_arg(*args):
        x = 0
        for arg in args:
            if isinstance(arg, int):
                x += arg
            if isinstance(arg, list):
                x += fn_ob_as_arg(*arg)

        return x

    req = Task(
        (TASK.NEW_FN | TASK.CALL_FN | TASK.OB_AS_ARG | TASK.DEL_FN),
        ["FN_SUM_ID", "OBJECT_ID", "OBJECT_ID"],
        fn_ob_as_arg, 10, 10, 10
    )
    resp = req.execute()
    assert [30 + sum(args)*2] == resp
    req = Task(TASK.CLEAR_CACHE)
    req.execute()


def test_ob_as_kwarg():
    req = Task((TASK.NEW_OB | TASK.CALL_FN),
               "OBJECT_ID", int)
    req.execute()

    def fn_set():
        return 21

    req = Task(
        (TASK.NEW_FN | TASK.CALL_FN | TASK.SET_OB),
        ["FN_SET_ID", "OBJECT_ID"], fn_set)
    req.execute()

    def fn_kwarg(RANDOM=None, OBJECT_ID=None):
        print(RANDOM, OBJECT_ID)
        assert OBJECT_ID is not None
        assert RANDOM is None

    req = Task(
        (TASK.CALL_FN | TASK.DEL_FN | TASK.OB_AS_KWARG),
        "FN_ID", fn_kwarg)
    req.execute()

    req = Task(TASK.CLEAR_CACHE)
    req.execute()


def _main():
    test_ob_as_arg()
    test_ob_as_kwarg()
    test_obj_assignment()
    test_serialization()
    test_filter_func()
    test_func2string()
    test_string2func()
    test_request_registration()
    test_request_call()
    test_request_call_fnames()
    test_clear_cache()


if __name__ == '__main__':
    _main()
