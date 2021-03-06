#encoding: utf-8
"""Tornado handlers for viewing HTML files."""

# Copyright (c) Jupyter Development Team.
# Distributed under the terms of the Modified BSD License.

from tornado import web
from jupyter_server.base.handlers import path_regex
from jupyter_server.utils import url_escape, url_path_join

from ..base.handlers import NotebookExtensionHandler

class ViewHandler(NotebookExtensionHandler):
    """Render HTML files within an iframe."""
    @web.authenticated
    def get(self, path):
        path = path.strip('/')
        if not self.contents_manager.file_exists(path):
            raise web.HTTPError(404, u'File does not exist: %s' % path)

        basename = path.rsplit('/', 1)[-1]
        file_url = url_path_join(self.base_url, 'files', url_escape(path))
        self.write(
            self.render_template('view.html', file_url=file_url, page_title=basename)
        )

default_handlers = [
    (r"/view%s" % path_regex, ViewHandler),
]
