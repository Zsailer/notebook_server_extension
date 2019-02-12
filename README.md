# Jupyter notebook server extension

**The classic notebook as a server extension.** 

This repo is **experimental** and meant to demonstrate how the notebook could be launched as a frontend+server extension. It is a fork of the classic notebook, refactored to use the `jupyter_server` and `jupyter_server_extension` dependencies. 

## Install

**Important**: use a virtual environment to avoid messing with your actually notebook installation. 

## Ways to launch

1. Run the notebook app directly.
    ```
    jupyter notebook
    ```

2. Use jupyter server to launch the notebook.

    Make sure the notebook is enabled.
    ```
    jupyter server extension list
    jupyter nbextension list
    ```

    If the frontend extensions or server extension is not enabled, enable them!
    ```
    # Enable the frontend extension
    jupyter nbextension enable notebookext --sys-prefix

    # Enable the server extension
    jupyter server extension enable notebookext
    ```

    Then run with the default URL set to the notebook tree:
    ```
    jupyter server --default_url="/tree"
    ```

## How does it work?

Here's a short list of what's happening" 
* All handlers inherit from the `JupyterExtensionHandler` (i.e. [see here](https://github.com/Zsailer/notebook_server_extension/blob/master/notebook/base/handlers.py))
* `NotebookApp` inherits from `JupyterExtensionApp`. 
* `load_jupyter_server_extension` loads config and appends handlers to jupyter server.

