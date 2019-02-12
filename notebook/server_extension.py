

import os
import gettext

from tornado import web

from ipython_genutils import py3compat
from jupyter_server.utils import url_path_join
from jupyter_server.base.handlers import FileFindHandler

from jinja2 import Environment, FileSystemLoader


# def _jupyter_server_extension_paths():
#     return [{
#         "module": "notebook_server_extension"
#     }]


def load_handlers(name):
    """Load the (URL pattern, handler) tuples for each component."""
    mod = __import__(name, fromlist=['default_handlers'])
    return mod.default_handlers


def load_jupyter_server_extension(serverapp):
    """Load the notebook application and notebook handlers.
    """
    from .notebookapp import NotebookApp

    extension = NotebookApp()
    extension.initialize_config()

    _template_path = extension.template_file_path
    if isinstance(_template_path, py3compat.string_types):
        _template_path = (_template_path,)
    template_path = [os.path.expanduser(path) for path in _template_path]

    jenv_opt = {"autoescape": True}

    base_dir = os.path.realpath(os.path.join(__file__, '..', '..'))
    dev_mode = os.path.exists(os.path.join(base_dir, '.git'))

    env = Environment(loader=FileSystemLoader(template_path), extensions=['jinja2.ext.i18n'], **jenv_opt)
    nbui = gettext.translation('nbui', localedir=os.path.join(
        base_dir, 'jupyter_server/i18n'), fallback=True)
    env.install_gettext_translations(nbui, newstyle=False)

    settings = {
        "notebook_static_path": extension.static_file_path,
        "notebook_template_path": template_path,
        "notebook_jinja2_env": env
    }

    # Pass settings to webapp.
    webapp = serverapp.web_app
    webapp.settings.update(settings)

    # Get notebook handlers.
    handlers = []
    handlers.extend([(r"/login", extension.login_handler_class)])
    handlers.extend([(r"/logout", extension.logout_handler_class)])
    handlers.extend(load_handlers('notebook.tree.handlers'))
    handlers.extend(load_handlers('notebook.notebook.handlers'))

    # Add a handler for notebook static files.
    handlers.append(
        (r"/static/notebook/(.*)", 
        webapp.settings['static_handler_class'], 
        {"path": extension.static_file_path})
    )

    # Add handlers to jupyter web application.
    webapp.add_handlers(".*$", handlers)
