#!/bin/sh

chmod +x ./geolocate.py
ln -s $(pwd)/geolocate.py /usr/bin/geolocate

echo "Installation Successful"