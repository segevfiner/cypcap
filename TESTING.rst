Testing Setup
=============
.. code-block:: shell

    virtualenv venv
    pip install -e .[dev]

    # Make the virtualenv Python a real file rather than a symlink
    [ -L "$1" ] && cp --remove-destination "$(readlink "venv/bin/python")" "venv/bin/python"

    # Give the virtualenv Python CAP_NET_RAW


    sudo setcap CAP_NET_RAW+ep venv/bin/python

    # Configure the dummy0 interface
    sudo ip link add dummy0 type dummy # Skip on WSL2, it has a pre-created dummy0
    sudo ip link set dummy0 up
    sudo ip addr add 172.27.224.1 dev dummy0

Run pytest with `--interface=<iface>`, e.g. `--interface=dummy0`

VS Code
-------
``.vscode/setting.json``:

.. code-block:: json

    {
        "python.testing.pytestArgs": [
            "--interface=dummy0"
        ],
        "python.testing.unittestEnabled": false,
        "python.testing.pytestEnabled": true,
    }

(You can of course add any other pytest flag you want)
