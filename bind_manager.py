#!/usr/bin/env python2

from werkzeug.serving import run_simple
from werkzeug.wsgi import DispatcherMiddleware
from bind_manager_v3 import app
from bind_manager_v3.modules.config import configuration
import os
import sys

config = configuration("/home/jaakko/Code/bind_manager_v3/bind_manager_v3/bind_manager.cfg")
configureta = config.get_options()

BIND = "0.0.0.0"
PORT = 7000
CONTEXT = "/bind-manager"

def simple(env, resp):
    resp(b'200 OK', [(b'Content-Type', b'text/html')])
    return [b"WSGI"]


parent_app = DispatcherMiddleware(simple, {CONTEXT: app})

if __name__ == "__main__":
    print "Context: %s" % (CONTEXT)
    run_simple(BIND, PORT, parent_app, use_reloader = True)



