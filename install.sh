#!/bin/sh

pip3 install -r requirements.txt
chmod +x ./geolocate.py
ln -s $(pwd)/geolocate.py /usr/bin/geolocate

echo "Installation Successful"