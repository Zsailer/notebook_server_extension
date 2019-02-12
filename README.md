# Jupyter notebook server extension

**The classic notebook as a server extension.** 

This repo is **experimental** and meant to demonstrate how the notebook could be launched as a frontend+server extension. 

## Ways to launch

1. Run the notebook app directly.
    ```
    jupyter notebookext
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