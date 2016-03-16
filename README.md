# dodscp
Steam Game Server Control Panel

dodscp is a web-based control panel for administering [LGSM](http://gameservermanagers.com/) game servers. It is 
written in Python using Flask.

## Installation

1. Download a copy of the [latest release](https://github.com/seancallaway/dodscp/releases/latest) and extract it to your server.
2. Enter this folder, setup a virtual environment (e.g. `virtualenv venv`), and activate it (e.g. `source venv/bin/activate`).
3. Ensure `setup.sh` is executable and run it (`./setup.sh`)
4. Point your web server at DODSCP.

For detailed instructions, see the [wiki](https://github.com/seancallaway/dodscp/wiki/Installation).

## Configuration

Configuration is handled by the `configure.py` script, which is called by `setup.sh`. It is an interactive script that 
sets up your DODSCP install.
