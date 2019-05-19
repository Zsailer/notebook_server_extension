from jupyter_server.extension.handler import ExtensionHandler


class NotebookExtensionHandler(ExtensionHandler):
    """Base handler for the notebook extension.
    """
    extension_name = "notebook"

    def get_template(self, name):
        """Return the jinja template object for a given name"""
        env = self.settings['{}_jinja2_env'.format(self.extension_name)]
        return env.get_template(name)