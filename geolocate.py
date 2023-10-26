#!/usr/bin/env python3

import os
import re
import socket
import requests
import datetime
import argparse
import geoip2.database
from termcolor import colored
from urllib.parse import urlparse

ip = ''
url = ''
hostname = ''
api = 'http://ip-api.com/json/{}?fields=66846719'
maps = 'https://www.google.com/maps/place/{0},{1}/@{0},{1}.16z'

def getDataIpapi():
	data = requests.get(api.format(ip)).json()

	if data['status'] == 'success':
		print('')
		print(colored('Source          : ', 'red') + 'ip-api')
		print(colored('IP              : ', 'green') + str(ip))
		print(colored('Hostname        : ', 'green') + str(hostname))
		print(colored('Contient Code   : ', 'green') + str(data['continentCode']))
		print(colored('Contient Name   : ', 'green') + str(data['continent']))
		print(colored('Country Code    : ', 'green') + str(data['countryCode']))
		print(colored('Country Name    : ', 'green') + str(data['country']))
		print(colored('Region Code     : ', 'green') + str(data['region']))
		print(colored('Region Name     : ', 'green') + str(data['regionName']))
		print(colored('City Name       : ', 'green') + str(data['city']))
		print(colored('District        : ', 'green') + str(data['district']))
		print(colored('Postal Code     : ', 'green') + str(data['zip']))
		print(colored('Time Zone       : ', 'green') + str(data['timezone']))
		print(colored('Offset          : ', 'green') + str(data['offset']))
		print(colored('Currency        : ', 'green') + str(data['currency']))
		print(colored('Latitude        : ', 'green') + str(data['lat']))
		print(colored('Longitude       : ', 'green') + str(data['lon']))
		print(colored('View on Maps    : ', 'green') + str(maps.format(data['lat'], data['lon'])))
		print(colored('ISP             : ', 'green') + str(data['isp']))
		print(colored('ORG             : ', 'green') + str(data['org']))
		print(colored('AS              : ', 'green') + str(data['as']))
		print(colored('AS Name         : ', 'green') + str(data['asname']))
		print(colored('Reverse         : ', 'green') + str(data['reverse']))
		print(colored('Mobile          : ', 'green') + str(data['mobile']))
		print(colored('Proxy           : ', 'green') + str(data['proxy']))
		print(colored('Hosting         : ', 'green') + str(data['hosting']))
	else:
		print('An error occurred while fetching data. Try again. If the error persists, use the [-m] flag to use the local maxmind database.')

def getDataMaxmind():
	with geoip2.database.Reader('/var/lib/GeoIP/GeoLite2-City.mmdb') as reader:
		response = reader.city(ip)
		print('')
		print(colored('Source          : ', 'red') + 'MaxMind')
		print(colored('IP              : ', 'green') + str(ip))
		print(colored('Hostname        : ', 'green') + str(hostname))
		print(colored('Contient Code   : ', 'green') + str(response.continent.code))
		print(colored('Contient Name   : ', 'green') + str(response.continent.name))
		print(colored('Country Code    : ', 'green') + str(response.country.iso_code))
		print(colored('Country Name    : ', 'green') + str(response.country.name))
		print(colored('Region Code     : ', 'green') + str(response.subdivisions.most_specific.iso_code))
		print(colored('Region Name     : ', 'green') + str(response.subdivisions.most_specific.name))
		print(colored('City Name       : ', 'green') + str(response.city.name))
		print(colored('Postal Code     : ', 'green') + str(response.postal.code))
		print(colored('Time Zone       : ', 'green') + str(response.location.time_zone))
		print(colored('Latitude        : ', 'green') + str(response.location.latitude))
		print(colored('Longitude       : ', 'green') + str(response.location.longitude))
		print(colored('View on Maps    : ', 'green') + str(maps.format(response.location.latitude, response.location.longitude)))

	with geoip2.database.Reader('/var/lib/GeoIP/GeoLite2-ASN.mmdb') as reader:
		response = reader.asn(ip)
		print(colored('ASN             : ', 'green') + str(response.autonomous_system_organization))



def main():
	global ip
	global url
	global hostname
	global maxmind

	parser = argparse.ArgumentParser()

	parser.add_argument('-i', '--ip', help= 'ip address', required= False)
	parser.add_argument('-u', '--url', help= 'url or hostname', required= False)
	parser.add_argument('-m', '--maxmind', help= 'use the maxmind', action='store_true', required= False)

	args = parser.parse_args()

	if(args.ip):
		ip = args.ip
		hostname = ip
	elif(args.url):
		url = args.url
		
		if not re.search(r'^[A-Za-z0-9+.\-]+://', url):
			url = 'https://{0}'.format(url)
		
		hostname = urlparse(url).hostname
		ip = socket.gethostbyname(str(hostname))
	else:
		parser.error('-i[ip] or -u[url] must be set')

	if(args.maxmind):
		ntime = datetime.datetime.now()
		mtime = datetime.datetime.fromtimestamp(os.path.getmtime('/var/lib/GeoIP/GeoLite2-City.mmdb'))
		dtime = ntime - mtime

		if dtime.days > 15:
			ch = input('MaxMindDB seems like not up to date. Would you like to update?(y/N)')
			if ch == 'y':
				os.system('geoipupdate')

		getDataMaxmind()
	else:
		getDataIpapi()


if __name__ == '__main__':
	main()
