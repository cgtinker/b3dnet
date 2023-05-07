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
    ob = Request(
        (REQUEST.REGISTER | REQUEST.CALL | REQUEST.UNREGISTER),
        "EXAMPLE_FUNCTION", fn, 1, 2, 3, 4, 5, a=2, b=12, d=3)

    b = ob.to_bytes()
    r = Request.from_bytes(b)
    assert r == ob


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
    req = Request(
        REQUEST.REGISTER,
        "SOME_ID",
        fn,
        1, 2, 3)
    req.execute()
    assert CACHE["SOME_ID"] == fn

    req = Request(
        REQUEST.UNREGISTER,
        "SOME_ID")
    req.execute()
    assert "SOME_ID" not in CACHE


def test_request_call():
    def fn(*args):
        return args

    req = Request(
        (REQUEST.REGISTER | REQUEST.CALL),
        "SOME_ID",
        fn,
        1, 2, 3)
    resp = req.execute()
    assert resp == fn(1, 2, 3)
    req = Request(
        REQUEST.CALL,
        "SOME_ID",
        None,
        1, 2, 3)
    resp = req.execute()
    assert resp == fn(1, 2, 3)


def test_request_call_fnames():
    def fn(*args, hello, world):
        return sum(args) + hello + world

    req = Request(
        (REQUEST.REGISTER | REQUEST.CALL),
        "SOME_ID",
        fn,
        1, 2, 3, hello=21, world=32)
    resp = req.execute()
    assert resp == fn(1, 2, 3, hello=21, world=32)
    req = Request(
        REQUEST.CALL,
        "SOME_ID",
        None,
        1, 2, 3, hello=21, world=32)
    resp = req.execute()
    assert resp == fn(1, 2, 3, hello=21, world=32)
    req = Request(REQUEST.CLEAR_CACHE)
    resp = req.execute()


def test_clear_cache():
    req = Request(REQUEST.CLEAR_CACHE)
    req.execute()

    def fn(*args):
        return args
    req = Request(
        (REQUEST.REGISTER | REQUEST.UNREGISTER), "_SOME_ID1", fn)

    req.execute()
    req = Request(REQUEST.REGISTER, "_SOME_ID2", fn)
    req.execute()
    req = Request(REQUEST.REGISTER, "_SOME_ID3", fn)
    req.execute()
    req = Request(REQUEST.REGISTER, "_SOME_ID4", fn)
    req.execute()
    req = Request(REQUEST.REGISTER, "_SOME_ID5", fn)
    req.execute()

    assert len(CACHE) == 4
    req = Request(REQUEST.CLEAR_CACHE)
    req.execute()
    assert len(CACHE) == 0


def _main():
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
