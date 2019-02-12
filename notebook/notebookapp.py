# coding: utf-8
"""A tornado based Jupyter notebook server."""

# Copyright (c) Jupyter Development Team.
# Distributed under the terms of the Modified BSD License.

from __future__ import absolute_import, print_function

import notebook
import binascii
import datetime
import errno
import gettext
import hashlib
import hmac
import importlib
import io
import ipaddress
import json
import logging
import mimetypes
import os
import random
import re
import select
import signal
import socket
import sys
import tempfile
import threading
import time
import warnings
import webbrowser

try: #PY3
    from base64 import encodebytes
except ImportError: #PY2
    from base64 import encodestring as encodebytes


from jinja2 import Environment, FileSystemLoader

from jupyter_server.transutils import trans, _

# Install the pyzmq ioloop. This has to be done before anything else from
# tornado is imported.
from zmq.eventloop import ioloop
ioloop.install()

# check for tornado 3.1.0
try:
    import tornado
except ImportError:
    raise ImportError(_("The Jupyter Notebook requires tornado >= 4.0"))
try:
    version_info = tornado.version_info
except AttributeError:
    raise ImportError(_("The Jupyter Notebook requires tornado >= 4.0, but you have < 1.1.0"))
if version_info < (4,0):
    raise ImportError(_("The Jupyter Notebook requires tornado >= 4.0, but you have %s") % tornado.version)

from tornado import httpserver
from tornado import web
from tornado.httputil import url_concat
from tornado.log import LogFormatter, app_log, access_log, gen_log

from notebook import (
    DEFAULT_STATIC_FILES_PATH,
    DEFAULT_TEMPLATE_PATH_LIST,
    __version__,
)

# py23 compatibility
try:
    raw_input = raw_input
except NameError:
    raw_input = input

from jupyter_server.log import log_request

from .auth.login import LoginHandler
from .auth.logout import LogoutHandler

from traitlets.config import Config
from traitlets.config.application import catch_config_error, boolean_flag
from jupyter_core.application import (
    base_flags, base_aliases,
)
from jupyter_core.paths import jupyter_config_path
from jupyter_client import KernelManager
from jupyter_client.kernelspec import KernelSpecManager, NoSuchKernel, NATIVE_KERNEL_NAME
from jupyter_client.session import Session
from nbformat.sign import NotebookNotary
from traitlets import (
    Any, Dict, Unicode, Integer, List, Bool, Bytes, Instance,
    TraitError, Type, Float, observe, default, validate
)
from ipython_genutils import py3compat
from jupyter_core.paths import jupyter_runtime_dir, jupyter_path
from notebook._sysinfo import get_sys_info

from jupyter_server._tz import utcnow, utcfromtimestamp
from jupyter_server.utils import url_path_join, check_pid, url_escape, urljoin, pathname2url

from jupyter_server_extension.application import JupyterServerExtensionApp

from .server_extension import load_jupyter_server_extension

#-----------------------------------------------------------------------------
# Module globals
#-----------------------------------------------------------------------------

_examples = """
jupyter notebook                       # start the notebook
jupyter notebook --certfile=mycert.pem # use SSL/TLS certificate
jupyter notebook password              # enter a password to protect the server
"""

#-----------------------------------------------------------------------------
# Aliases and Flags
#-----------------------------------------------------------------------------

flags = dict(base_flags)
flags['no-browser']=(
    {'NotebookApp' : {'open_browser' : False}},
    _("Don't open the notebook in a browser after startup.")
)
flags['pylab']=(
    {'NotebookApp' : {'pylab' : 'warn'}},
    _("DISABLED: use %pylab or %matplotlib in the notebook to enable matplotlib.")
)
flags['no-mathjax']=(
    {'NotebookApp' : {'enable_mathjax' : False}},
    """Disable MathJax
    
    MathJax is the javascript library Jupyter uses to render math/LaTeX. It is
    very large, so you may want to disable it if you have a slow internet
    connection, or for offline use of the notebook.
    
    When disabled, equations etc. will appear as their untransformed TeX source.
    """
)

flags['allow-root']=(
    {'NotebookApp' : {'allow_root' : True}},
    _("Allow the notebook to be run from root user.")
)

# Add notebook manager flags
flags.update(boolean_flag('script', 'FileContentsManager.save_script',
               'DEPRECATED, IGNORED',
               'DEPRECATED, IGNORED'))

aliases = dict(base_aliases)


#-----------------------------------------------------------------------------
# NotebookApp
#-----------------------------------------------------------------------------

class NotebookExtApp(JupyterServerExtensionApp):

    name = 'jupyter-notebook'
    version = __version__
    description = _("""The Jupyter HTML Notebook.
    
    This launches a Tornado based HTML Notebook Server that serves up an HTML5/Javascript Notebook client.""")
    examples = _examples
    aliases = aliases
    flags = flags

    load_jupyter_server_extension = staticmethod(load_jupyter_server_extension)

    # file to be opened in the notebook server
    file_to_run = Unicode('', config=True)

    # Network related information
    allow_origin = Unicode('', config=True,
        help="""Set the Access-Control-Allow-Origin header
        
        Use '*' to allow any origin to access your server.
        
        Takes precedence over allow_origin_pat.
        """
    )
    
    allow_origin_pat = Unicode('', config=True,
        help="""Use a regular expression for the Access-Control-Allow-Origin header
        
        Requests from an origin matching the expression will get replies with:
        
            Access-Control-Allow-Origin: origin
        
        where `origin` is the origin of the request.
        
        Ignored if allow_origin is set.
        """
    )
    
    allow_credentials = Bool(False, config=True,
        help=_("Set the Access-Control-Allow-Credentials: true header")
    )
    
    allow_root = Bool(False, config=True, 
        help=_("Whether to allow the user to run the notebook as root.")
    )

    default_url = Unicode('/tree', config=True,
        help=_("The default URL to redirect to from `/`")
    )
    
    ip = Unicode('localhost', config=True,
        help=_("The IP address the notebook server will listen on.")
    )

    @default('ip')
    def _default_ip(self):
        """Return localhost if available, 127.0.0.1 otherwise.
        
        On some (horribly broken) systems, localhost cannot be bound.
        """
        s = socket.socket()
        try:
            s.bind(('localhost', 0))
        except socket.error as e:
            self.log.warning(_("Cannot bind to localhost, using 127.0.0.1 as default ip\n%s"), e)
            return '127.0.0.1'
        else:
            s.close()
            return 'localhost'

    @validate('ip')
    def _valdate_ip(self, proposal):
        value = proposal['value']
        if value == u'*':
            value = u''
        return value

    custom_display_url = Unicode(u'', config=True,
        help=_("""Override URL shown to users.

        Replace actual URL, including protocol, address, port and base URL,
        with the given value when displaying URL to the users. Do not change
        the actual connection URL. If authentication token is enabled, the
        token is added to the custom URL automatically.

        This option is intended to be used when the URL to display to the user
        cannot be determined reliably by the Jupyter notebook server (proxified
        or containerized setups for example).""")
    )

    port = Integer(8888, config=True,
        help=_("The port the notebook server will listen on.")
    )

    port_retries = Integer(50, config=True,
        help=_("The number of additional ports to try if the specified port is not available.")
    )

    certfile = Unicode(u'', config=True, 
        help=_("""The full path to an SSL/TLS certificate file.""")
    )
    
    keyfile = Unicode(u'', config=True, 
        help=_("""The full path to a private key file for usage with SSL/TLS.""")
    )
    
    client_ca = Unicode(u'', config=True,
        help=_("""The full path to a certificate authority certificate for SSL/TLS client authentication.""")
    )
    
    cookie_secret_file = Unicode(config=True,
        help=_("""The file where the cookie secret is stored.""")
    )

    @default('cookie_secret_file')
    def _default_cookie_secret_file(self):
        return os.path.join(self.runtime_dir, 'notebook_cookie_secret')

    cookie_secret = Bytes(b'', config=True,
        help="""The random bytes used to secure cookies.
        By default this is a new random number every time you start the Notebook.
        Set it to a value in a config file to enable logins to persist across server sessions.

        Note: Cookie secrets should be kept private, do not share config files with
        cookie_secret stored in plaintext (you can read the value from a file).
        """
    )

    @default('cookie_secret')
    def _default_cookie_secret(self):
        if os.path.exists(self.cookie_secret_file):
            with io.open(self.cookie_secret_file, 'rb') as f:
                key =  f.read()
        else:
            key = encodebytes(os.urandom(32))
            self._write_cookie_secret_file(key)
        h = hmac.new(key, digestmod=hashlib.sha256)
        h.update(self.password.encode())
        return h.digest()

    def _write_cookie_secret_file(self, secret):
        """write my secret to my secret_file"""
        self.log.info(_("Writing notebook server cookie secret to %s"), self.cookie_secret_file)
        try:
            with io.open(self.cookie_secret_file, 'wb') as f:
                f.write(secret)
        except OSError as e:
            self.log.error(_("Failed to write cookie secret to %s: %s"),
                           self.cookie_secret_file, e)
        try:
            os.chmod(self.cookie_secret_file, 0o600)
        except OSError:
            self.log.warning(
                _("Could not set permissions on %s"),
                self.cookie_secret_file
            )

    token = Unicode('<generated>',
        help=_("""Token used for authenticating first-time connections to the server.

        When no password is enabled,
        the default is to generate a new, random token.

        Setting to an empty string disables authentication altogether, which is NOT RECOMMENDED.
        """)
    ).tag(config=True)

    _token_generated = True

    @default('token')
    def _token_default(self):
        if os.getenv('JUPYTER_TOKEN'):
            self._token_generated = False
            return os.getenv('JUPYTER_TOKEN')
        if self.password:
            # no token if password is enabled
            self._token_generated = False
            return u''
        else:
            self._token_generated = True
            return binascii.hexlify(os.urandom(24)).decode('ascii')

    max_body_size = Integer(512 * 1024 * 1024, config=True,
        help="""
        Sets the maximum allowed size of the client request body, specified in 
        the Content-Length request header field. If the size in a request 
        exceeds the configured value, a malformed HTTP message is returned to
        the client.

        Note: max_body_size is applied even in streaming mode.
        """
    )

    max_buffer_size = Integer(512 * 1024 * 1024, config=True,
        help="""
        Gets or sets the maximum amount of memory, in bytes, that is allocated 
        for use by the buffer manager.
        """
    )

    @observe('token')
    def _token_changed(self, change):
        self._token_generated = False

    password = Unicode(u'', config=True,
                      help="""Hashed password to use for web authentication.

                      To generate, type in a python/IPython shell:

                        from notebook.auth import passwd; passwd()

                      The string should be of the form type:salt:hashed-password.
                      """
    )

    password_required = Bool(False, config=True,
                      help="""Forces users to use a password for the Notebook server.
                      This is useful in a multi user environment, for instance when
                      everybody in the LAN can access each other's machine through ssh.

                      In such a case, server the notebook server on localhost is not secure
                      since any user can connect to the notebook server via ssh.

                      """
    )

    allow_password_change = Bool(True, config=True, 
                    help="""Allow password to be changed at login for the notebook server. 

                    While loggin in with a token, the notebook server UI will give the opportunity to
                    the user to enter a new password at the same time that will replace
                    the token login mechanism. 

                    This can be set to false to prevent changing password from the UI/API.
                    """
    )


    disable_check_xsrf = Bool(False, config=True,
        help="""Disable cross-site-request-forgery protection

        Jupyter notebook 4.3.1 introduces protection from cross-site request forgeries,
        requiring API requests to either:

        - originate from pages served by this server (validated with XSRF cookie and token), or
        - authenticate with a token

        Some anonymous compute resources still desire the ability to run code,
        completely without authentication.
        These services can disable all authentication and security checks,
        with the full knowledge of what that implies.
        """
    )

    allow_remote_access = Bool(config=True,
       help="""Allow requests where the Host header doesn't point to a local server

       By default, requests get a 403 forbidden response if the 'Host' header
       shows that the browser thinks it's on a non-local domain.
       Setting this option to True disables this check.

       This protects against 'DNS rebinding' attacks, where a remote web server
       serves you a page and then changes its DNS to send later requests to a
       local IP, bypassing same-origin checks.

       Local IP addresses (such as 127.0.0.1 and ::1) are allowed as local,
       along with hostnames configured in local_hostnames.
       """)

    @default('allow_remote_access')
    def _default_allow_remote(self):
        """Disallow remote access if we're listening only on loopback addresses"""

        # if blank, self.ip was configured to "*" meaning bind to all interfaces,
        # see _valdate_ip
        if self.ip == "":
            return True

        try:
            addr = ipaddress.ip_address(self.ip)
        except ValueError:
            # Address is a hostname
            for info in socket.getaddrinfo(self.ip, self.port, 0, socket.SOCK_STREAM):
                addr = info[4][0]
                if not py3compat.PY3:
                    addr = addr.decode('ascii')

                try:
                    parsed = ipaddress.ip_address(addr.split('%')[0])
                except ValueError:
                    self.log.warning("Unrecognised IP address: %r", addr)
                    continue

                # Macs map localhost to 'fe80::1%lo0', a link local address
                # scoped to the loopback interface. For now, we'll assume that
                # any scoped link-local address is effectively local.
                if not (parsed.is_loopback
                        or (('%' in addr) and parsed.is_link_local)):
                    return True
            return False
        else:
            return not addr.is_loopback

    open_browser = Bool(True, config=True,
                        help="""Whether to open in a browser after starting.
                        The specific browser used is platform dependent and
                        determined by the python standard library `webbrowser`
                        module, unless it is overridden using the --browser
                        (NotebookApp.browser) configuration option.
                        """)

    browser = Unicode(u'', config=True,
                      help="""Specify what command to use to invoke a web
                      browser when opening the notebook. If not specified, the
                      default browser will be determined by the `webbrowser`
                      standard library module, which allows setting of the
                      BROWSER environment variable to override it.
                      """)

    webbrowser_open_new = Integer(2, config=True,
        help=_("""Specify Where to open the notebook on startup. This is the
        `new` argument passed to the standard library method `webbrowser.open`.
        The behaviour is not guaranteed, but depends on browser support. Valid
        values are:

         - 2 opens a new tab,
         - 1 opens a new window,
         - 0 opens in an existing window.

        See the `webbrowser.open` documentation for details.
        """))

    webapp_settings = Dict(config=True,
        help=_("DEPRECATED, use tornado_settings")
    )

    @observe('webapp_settings') 
    def _update_webapp_settings(self, change):
        self.log.warning(_("\n    webapp_settings is deprecated, use tornado_settings.\n"))
        self.tornado_settings = change['new']
    
    tornado_settings = Dict(config=True,
            help=_("Supply overrides for the tornado.web.Application that the "
                 "Jupyter notebook uses."))

    websocket_compression_options = Any(None, config=True,
        help=_("""
        Set the tornado compression options for websocket connections.

        This value will be returned from :meth:`WebSocketHandler.get_compression_options`.
        None (default) will disable compression.
        A dict (even an empty one) will enable compression.

        See the tornado docs for WebSocketHandler.get_compression_options for details.
        """)
    )
    terminado_settings = Dict(config=True,
            help=_('Supply overrides for terminado. Currently only supports "shell_command".'))

    cookie_options = Dict(config=True,
        help=_("Extra keyword arguments to pass to `set_secure_cookie`."
             " See tornado's set_secure_cookie docs for details.")
    )
    get_secure_cookie_kwargs = Dict(config=True,
        help=_("Extra keyword arguments to pass to `get_secure_cookie`."
             " See tornado's get_secure_cookie docs for details.")
    )
    ssl_options = Dict(config=True,
            help=_("""Supply SSL options for the tornado HTTPServer.
            See the tornado docs for details."""))
    
    jinja_environment_options = Dict(config=True, 
            help=_("Supply extra arguments that will be passed to Jinja environment."))

    jinja_template_vars = Dict(
        config=True,
        help=_("Extra variables to supply to jinja templates when rendering."),
    )
    
    enable_mathjax = Bool(True, config=True,
        help="""Whether to enable MathJax for typesetting math/TeX

        MathJax is the javascript library Jupyter uses to render math/LaTeX. It is
        very large, so you may want to disable it if you have a slow internet
        connection, or for offline use of the notebook.

        When disabled, equations etc. will appear as their untransformed TeX source.
        """
    )

    @observe('enable_mathjax')
    def _update_enable_mathjax(self, change):
        """set mathjax url to empty if mathjax is disabled"""
        if not change['new']:
            self.mathjax_url = u''

    base_url = Unicode('/', config=True,
                               help='''The base URL for the notebook server.

                               Leading and trailing slashes can be omitted,
                               and will automatically be added.
                               ''')

    @validate('base_url')
    def _update_base_url(self, proposal):
        value = proposal['value']
        if not value.startswith('/'):
            value = '/' + value
        if not value.endswith('/'):
            value = value + '/'
        return value
    
    base_project_url = Unicode('/', config=True, help=_("""DEPRECATED use base_url"""))

    @observe('base_project_url')
    def _update_base_project_url(self, change):
        self.log.warning(_("base_project_url is deprecated, use base_url"))
        self.base_url = change['new']

    extra_static_paths = List(Unicode(), config=True,
        help="""Extra paths to search for serving static files.
        
        This allows adding javascript/css to be available from the notebook server machine,
        or overriding individual files in the IPython"""
    )
    
    @property
    def static_file_path(self):
        """return extra paths + the default location"""
        return self.extra_static_paths + [DEFAULT_STATIC_FILES_PATH]
    
    static_custom_path = List(Unicode(),
        help=_("""Path to search for custom.js, css""")
    )

    @default('static_custom_path')
    def _default_static_custom_path(self):
        return [
            os.path.join(d, 'custom') for d in (
                self.config_dir,
                DEFAULT_STATIC_FILES_PATH)
        ]

    extra_template_paths = List(Unicode(), config=True,
        help=_("""Extra paths to search for serving jinja templates.

        Can be used to override templates from notebook.templates.""")
    )

    @property
    def template_file_path(self):
        """return extra paths + the default locations"""
        return self.extra_template_paths + DEFAULT_TEMPLATE_PATH_LIST

    extra_nbextensions_path = List(Unicode(), config=True,
        help=_("""extra paths to look for Javascript notebook extensions""")
    )

    @property
    def nbextensions_path(self):
        """The path to look for Javascript notebook extensions"""
        path = self.extra_nbextensions_path + jupyter_path('nbextensions')
        # FIXME: remove IPython nbextensions path after a migration period
        try:
            from IPython.paths import get_ipython_dir
        except ImportError:
            pass
        else:
            path.append(os.path.join(get_ipython_dir(), 'nbextensions'))
        return path

    mathjax_url = Unicode("", config=True,
        help="""A custom url for MathJax.js.
        Should be in the form of a case-sensitive url to MathJax,
        for example:  /static/components/MathJax/MathJax.js
        """
    )

    @default('mathjax_url')
    def _default_mathjax_url(self):
        if not self.enable_mathjax:
            return u''
        static_url_prefix = self.tornado_settings.get("static_url_prefix", "static")
        return url_path_join(static_url_prefix, 'components', 'MathJax', 'MathJax.js')
    
    @observe('mathjax_url')
    def _update_mathjax_url(self, change):
        new = change['new']
        if new and not self.enable_mathjax:
            # enable_mathjax=False overrides mathjax_url
            self.mathjax_url = u''
        else:
            self.log.info(_("Using MathJax: %s"), new)

    mathjax_config = Unicode("TeX-AMS-MML_HTMLorMML-full,Safe", config=True,
        help=_("""The MathJax.js configuration file that is to be used.""")
    )

    @observe('mathjax_config')
    def _update_mathjax_config(self, change):
        self.log.info(_("Using MathJax configuration file: %s"), change['new'])
        
    quit_button = Bool(True, config=True,
        help="""If True, display a button in the dashboard to quit
        (shutdown the notebook server)."""
    )

    login_handler_class = Type(
        default_value=LoginHandler,
        klass=web.RequestHandler,
        config=True,
        help=_('The login handler class to use.'),
    )

    logout_handler_class = Type(
        default_value=LogoutHandler,
        klass=web.RequestHandler,
        config=True,
        help=_('The logout handler class to use.'),
    )

    trust_xheaders = Bool(False, config=True,
        help=(_("Whether to trust or not X-Scheme/X-Forwarded-Proto and X-Real-Ip/X-Forwarded-For headers"
              "sent by the upstream reverse proxy. Necessary if the proxy handles SSL"))
    )

    info_file = Unicode()

    @default('info_file')
    def _default_info_file(self):
        info_file = "nbserver-%s.json" % os.getpid()
        return os.path.join(self.runtime_dir, info_file)

    browser_open_file = Unicode()

    @default('browser_open_file')
    def _default_browser_open_file(self):
        basename = "nbserver-%s-open.html" % os.getpid()
        return os.path.join(self.runtime_dir, basename)
    
    pylab = Unicode('disabled', config=True,
        help=_("""
        DISABLED: use %pylab or %matplotlib in the notebook to enable matplotlib.
        """)
    )

    @observe('pylab')
    def _update_pylab(self, change):
        """when --pylab is specified, display a warning and exit"""
        if change['new'] != 'warn':
            backend = ' %s' % change['new']
        else:
            backend = ''
        self.log.error(_("Support for specifying --pylab on the command line has been removed."))
        self.log.error(
            _("Please use `%pylab{0}` or `%matplotlib{0}` in the notebook itself.").format(backend)
        )
        self.exit(1)

    notebook_dir = Unicode(config=True,
        help=_("The directory to use for notebooks and kernels.")
    )

    @default('notebook_dir')
    def _default_notebook_dir(self):
        if self.file_to_run:
            return os.path.dirname(os.path.abspath(self.file_to_run))
        else:
            return py3compat.getcwd()

    @validate('notebook_dir')
    def _notebook_dir_validate(self, proposal):
        value = proposal['value']
        # Strip any trailing slashes
        # *except* if it's root
        _, path = os.path.splitdrive(value)
        if path == os.sep:
            return value
        value = value.rstrip(os.sep)
        if not os.path.isabs(value):
            # If we receive a non-absolute path, make it absolute.
            value = os.path.abspath(value)
        if not os.path.isdir(value):
            raise TraitError(trans.gettext("No such notebook dir: '%r'") % value)
        return value

    @observe('notebook_dir')
    def _update_notebook_dir(self, change):
        """Do a bit of validation of the notebook dir."""
        # setting App.notebook_dir implies setting notebook and kernel dirs as well
        new = change['new']
        self.config.FileContentsManager.root_dir = new
        self.config.MappingKernelManager.root_dir = new

    iopub_msg_rate_limit = Float(1000, config=True, help=_("""(msgs/sec)
        Maximum rate at which messages can be sent on iopub before they are
        limited."""))

    iopub_data_rate_limit = Float(1000000, config=True, help=_("""(bytes/sec)
        Maximum rate at which stream output can be sent on iopub before they are
        limited."""))

    rate_limit_window = Float(3, config=True, help=_("""(sec) Time window used to 
        check the message and data rate limits."""))

    shutdown_no_activity_timeout = Integer(0, config=True,
        help=("Shut down the server after N seconds with no kernels or "
              "terminals running and no activity. "
              "This can be used together with culling idle kernels "
              "(MappingKernelManager.cull_idle_timeout) to "
              "shutdown the notebook server when it's not in use. This is not "
              "precisely timed: it may shut down up to a minute later. "
              "0 (the default) disables this automatic shutdown.")
    )

    terminals_enabled = Bool(True, config=True,
         help=_("""Set to False to disable terminals.

         This does *not* make the notebook server more secure by itself.
         Anything the user can in a terminal, they can also do in a notebook.

         Terminals may also be automatically disabled if the terminado package
         is not available.
         """))

    # def init_terminals(self):
    #     if not self.terminals_enabled:
    #         return

    #     try:
    #         from .terminal import initialize
    #         initialize(self.web_app, self.notebook_dir, self.connection_url, self.terminado_settings)
    #         self.web_app.settings['terminals_available'] = True
    #     except ImportError as e:
    #         self.log.warning(_("Terminals not available (error was %s)"), e)



#-----------------------------------------------------------------------------
# Main entry point
#-----------------------------------------------------------------------------

main = launch_new_instance = NotebookAppExt.launch_instance
