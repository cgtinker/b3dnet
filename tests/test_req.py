from src.request import *


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
        (REQUEST_REGISTATION | REQUEST_CALL | REQUEST_UNREGISTRATION),
        "EXAMPLE_FUNCTION", fn, 1, 2, 3, 4, 5, a=2, b=12, d=3)

    b = request2bytes(ob)
    r = bytes2request(b)
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
    res = filter_func_str(fns)
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
    s = func2string(fn)
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
    comp_fn = string2func(comp)
    assert comp_fn is not None
    assert fn(1, 2, 3, a=3, b=1) == comp_fn(1, 2, 3, a=3, b=1)


def test_request_registration():
    def fn(*args):
        return args
    req = Request(
        REQUEST_REGISTATION,
        "SOME_ID",
        fn,
        1, 2, 3)
    handle_request(req)
    assert CACHE["SOME_ID"] == fn

    req = Request(
        REQUEST_UNREGISTRATION,
        "SOME_ID")
    handle_request(req)
    assert "SOME_ID" not in CACHE


def test_request_call():
    def fn(*args):
        return args

    req = Request(
        (REQUEST_REGISTATION | REQUEST_CALL),
        "SOME_ID",
        fn,
        1, 2, 3)
    resp = handle_request(req)
    assert resp == fn(1, 2, 3)
    req = Request(
        REQUEST_CALL,
        "SOME_ID",
        None,
        1, 2, 3)
    resp = handle_request(req)
    assert resp == fn(1, 2, 3)


def test_request_call_fnames():
    def fn(*args, hello, world):
        return sum(args) + hello + world

    req = Request(
        (REQUEST_REGISTATION | REQUEST_CALL),
        "SOME_ID",
        fn,
        1, 2, 3, hello=21, world=32)
    resp = handle_request(req)
    assert resp == fn(1, 2, 3, hello=21, world=32)
    req = Request(
        REQUEST_CALL,
        "SOME_ID",
        None,
        1, 2, 3, hello=21, world=32)
    resp = handle_request(req)
    assert resp == fn(1, 2, 3, hello=21, world=32)
    req = Request(REQUEST_CLEAR_CACHE)
    handle_request(req)


def test_clear_cache():
    req = Request(REQUEST_CLEAR_CACHE)
    handle_request(req)

    def fn(*args):
        return args
    req = Request(
        (REQUEST_REGISTATION | REQUEST_UNREGISTRATION), "_SOME_ID1", fn)

    handle_request(req)
    req = Request(REQUEST_REGISTATION, "_SOME_ID2", fn)
    handle_request(req)
    req = Request(REQUEST_REGISTATION, "_SOME_ID3", fn)
    handle_request(req)
    req = Request(REQUEST_REGISTATION, "_SOME_ID4", fn)
    handle_request(req)
    req = Request(REQUEST_REGISTATION, "_SOME_ID5", fn)
    handle_request(req)

    assert len(CACHE) == 4
    req = Request(REQUEST_CLEAR_CACHE)
    handle_request(req)
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
