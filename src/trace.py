#!/usr/bin/env python2

import collections
import math
import pygeoip
import sys
import time

from scapy.all import *

GOOGLE = "www.google.com"
EXACTAS = "dc.uba.ar"

# Universidades - http://www.webometrics.info/es/Europe

universities = {'Inglaterra' : 'www.ox.ac.uk',
				'Finlandia' : 'www.helsinki.fi',
				'Alemania' : 'www.uva.nl',
				'Belgica' : 'www.kuleuven.be',
				'Noruega' : 'www.uio.no',
				'Israel' : 'new.huji.ac.il',
				'Italia' : 'www.uniroma1.it',
				'Japon' : 'www.u-tokyo.ac.jp'
				 }


# Constantes

MAX_TTL = 255

ECHO_REPLY = 0
ECHO_REQUEST = 11

false = False
true = True

GEOIP_CITY_DAT = "GeoLiteCity.dat"

class Hop:
	ttl = 0
	packet = None
	rtt = 0.0
	rtti = 0.0
	geoip = None
	zscore = 0.0

	def __init__(self, **kwds):
		self.__dict__.update(kwds)

class Route:
	def __init__(self):
		self.hops = []
		self.geoip = pygeoip.GeoIP(GEOIP_CITY_DAT)

	def trace(self, hostname):
		self.clear()
		hasReply = true
		print "Route: " + hostname
		for ttl in range(1,MAX_TTL+1):
			packet = IP(dst=hostname, ttl=ttl) / ICMP()
			rtt = time.clock()
			answer = sr1(packet, timeout=1, verbose=0)
			rtt = time.clock() - rtt

			if answer:
				record = self.geoip.record_by_name(answer.src)
			
			self.hops.append(Hop(ttl=ttl, packet=answer, rtt=rtt, geoip=record, zscore=0.0))

			if answer:
				hop = str(answer.src)
				hop += "\t" + str(rtt)
				if record:
					hop += "\t" + str(record['time_zone'])
				print hop
			else:
				print "* * *"

			if answer and answer.type == ECHO_REPLY:
				hasReply = true
				break

		if hasReply:
			print "done!"
		else:
			print "fail."

	def zscore(self):

		last = None
		for hop in self.hops:
			if hop.packet:
				if last:
					hop.rtti = hop.rtt - last.rtt
				else:
					last = hop

		average = 0.0
		count = 0.0

		for hop in self.hops:
			if hop.packet:
				average += hop.rtti
				count += 1

		average = average / count

		variance = 0.0

		for hop in self.hops:
			if hop.packet:
				variance += pow(hop.rtti - average, 2)

		variance = variance / count

		print "Average: " + str(average).replace('.', ',')
		print "Variance: " + str(variance).replace('.', ',')
		print "Standard Deviation: " + str(math.sqrt(variance)).replace('.', ',')

		print "Average+SD: " + str(average + math.sqrt(variance)).replace('.', ',')
		print "Average-SD: " + str(average - math.sqrt(variance)).replace('.', ',')

		line = "IP"
		line += "\t" + "zscore"
		line += "\t" + "rtti"
		line += "\t" + "average"
		line += "\t" + "variance"
		line += "\t" + "Average+SD"
		line += "\t" + "Average-SD"
		print line

		for hop in self.hops:
			if hop.packet:
				hop.zscore = (hop.rtti - average) / math.sqrt(variance)
				line = str(hop.packet.src)
				
				if hop.geoip:
					line += "(" + str(hop.geoip['time_zone']) + ")"

				line += "\t" + str(hop.zscore).replace('.', ',')
				line += "\t" + str(hop.rtti).replace('.', ',')
				line += "\t" + str(average).replace('.', ',')
				line += "\t" + str(math.sqrt(variance)).replace('.', ',')
				line += "\t" + str(average + math.sqrt(variance)).replace('.', ',')
				line += "\t" + str(average - math.sqrt(variance)).replace('.', ',')
				print line #jeje

	def clear(self):
		self.hops = []

def main(argv=sys.argv):
	route = Route()

#	for university in universities:
#		route.trace(universities[university])
#		route.zscore()
#		print "-" * 80

	route.trace('www.uio.no')
	route.zscore()

if __name__ == '__main__':
	main()
