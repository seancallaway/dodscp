#!/bin/bash

echo "Installing prerequisites..."
pip install -r requirements.txt

echo "Starting DODSCP configuration script..."
python configure.py