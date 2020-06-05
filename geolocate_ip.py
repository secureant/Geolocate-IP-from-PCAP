import geoip2.database
from scapy.all import *
import argparse

def geoLocate(ips):
	reader = geoip2.database.Reader('GeoLite2-City.mmdb')

	for ip in ips:
		print('[+] Results for IP: ' + ip)

		resp = reader.city(ip)
		country = resp.country.name
		city = resp.city.name
		zip_code = resp.postal.code
		latitude = resp.location.latitude
		longitude = resp.location.longitude

		if country:
			print('    Country: ' + country)
		if city:
			print('    City: ' + city)
		if zip_code:
			print('    Zip Code: ' + zip_code)
		if latitude:
			print('    Latitude: ' + str(latitude))
		if longitude:
			print('    Longitude:' + str(longitude))

def pcapParse(packets):
	ips = []
	for pkt in packets:
		src = pkt[IP].src
		dst = pkt[IP].dst
		ips.append(src)
		ips.append(dst)
	geoLocate(ips)

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("-p", help="PCAP file")
	parser.add_argument
	args = parser.parse_args()
	pcap = args.p
	packets = rdpcap(pcap)
	pcapParse(packets)

if __name__ == '__main__':
	main()
