# import sys
# from . import request, tcpclient, tcpserver
#
#
# def flatten(a):
#     return [c for b in a for c in flatten(b)] if hasattr(a, '__iter__') else [a]
#
#
# __all__ = flatten([[x for x in dir(mod) if not x.startswith('_')]
#                   for mod in [request, tcpclient, tcpserver]])
#
#
# if '__main__' in sys.modules:
#     sys.modules['__mp_main__'] = sys.modules['__main__']
