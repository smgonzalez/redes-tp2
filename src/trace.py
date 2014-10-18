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

universities = {'inglaterra' : 'www.ox.ac.uk',
				'finlandia' : 'www.helsinki.fi',
				'alemania' : 'www.uva.nl',
				'belgica' : 'www.kuleuven.be',
				'noruega' : 'www.uio.no',
				'israel' : 'new.huji.ac.il',
				'italia' : 'www.uniroma1.it',
				'japon' : 'www.u-tokyo.ac.jp',
				'australia' : 'www.utas.edu.au'
				 }


# Constantes

MAX_TTL = 255

ECHO_REPLY = 0
ECHO_REQUEST = 11

false = False
true = True

GEOIP_CITY_DAT = "GeoLiteCity.dat"
REPEAT_COUNT = 3
CANT_NOT_REPLYS = 3

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
		
		self.hops = []

		hasReply = true
		print "Route: " + hostname

		cant_not_replys = 0
		for ttl in range(1,MAX_TTL+1):

			rtt_total = 0
			rtt_count = 0	
			for i in range(REPEAT_COUNT):
			
				packet = IP(dst=hostname, ttl=ttl) / ICMP()
				rtt = time.clock()
				answer = sr1(packet, timeout=1, verbose=0)
				rtt = time.clock() - rtt
				
				answer_ip = ""

				if answer:
					rtt_total += rtt
					rtt_count += 1
					answer_ip = answer.src
					cant_not_replys = 0
				else:
					cant_not_replys += 1


			if rtt_count > 0:
				rtt_prom = rtt_total / rtt_count
			else: 
				rtt_prom = 0

			record = None

			if answer:
				record = self.geoip.record_by_name(answer.src)
			
			self.hops.append(Hop(ttl=ttl, packet_ip=answer_ip, rtt=rtt_prom, geoip=record, zscore=0.0))

			if answer:
				hop = str(answer.src)
				hop += "\t" + str(rtt)
				if record:
					hop += "\t" + str(record['time_zone'])
				print hop
			else:
				print "* * *"

			if (answer and answer.type == ECHO_REPLY) or cant_not_replys >= CANT_NOT_REPLYS * REPEAT_COUNT:
				hasReply = true
				break

		if hasReply:
			print "done!"
		else:
			print "fail."

	def zscore(self):

		self.hops[0].rtti = self.hops[0].rtt
		last_rtt_not_zero = None

		for i in range(1, len(self.hops)):
			if self.hops[i].packet_ip != "":
				if self.hops[i].rtt < self.hops[i-1].rtt:
					self.hops[i].rtti = 0.0
				else:
		
					if not last_rtt_not_zero:
						self.hops[i].rtti = self.hops[i].rtt - last_rtt_not_zero
					else:
						self.hops[i].rtti = self.hops[i].rtt
					
				last_rtt_not_zero = self.hops[i].rtt
			else:
				self.hops[i].rtti = 0.0

		average = 0.0

		for hop in self.hops:
			average += hop.rtti

		average = average / float(len(self.hops))

		variance = 0.0

		for hop in self.hops:
			variance += pow(hop.rtti - average, 2)

		variance = variance / float(len(self.hops)-1)
		standard_deviation = math.sqrt(variance)

		print "Average: " + str(average).replace('.', ',')
		print "Variance: " + str(variance).replace('.', ',')
		print "Standard Deviation: " + str(standard_deviation).replace('.', ',')

		print "Average+SD: " + str(average + standard_deviation).replace('.', ',')
		print "Average-SD: " + str(average - standard_deviation).replace('.', ',')

		line = "IP"
		line += "\t" + "zscore"
		line += "\t" + "rtti"
		line += "\t" + "average"
		line += "\t" + "variance"
		line += "\t" + "Average+SD"
		line += "\t" + "Average-SD"
		print line

		for hop in self.hops:
			line = ""

			if hop.packet_ip != "":
				hop.zscore = (hop.rtti - average) / standard_deviation
				line += hop.packet_ip
				
				if hop.geoip:
					line += "(" + str(hop.geoip['time_zone']) + ")"

			else:
				line += "*"

			line += "\t" + str(hop.zscore).replace('.', ',')
			line += "\t" + str(hop.rtti).replace('.', ',')
			line += "\t" + str(average).replace('.', ',')
			line += "\t" + str(standard_deviation).replace('.', ',')
			line += "\t" + str(average + standard_deviation).replace('.', ',')
			line += "\t" + str(average - standard_deviation).replace('.', ',')
			
			print line

def main(argv=sys.argv):
	route = Route()

	route.trace(universities[argv[1]])
	route.zscore()

#	for university in universities:
#		route.trace(universities[university])
#		route.zscore()
#		print "-" * 80

if __name__ == '__main__':
	main()
