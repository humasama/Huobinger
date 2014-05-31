#!/usr/bin/python
import os,sys

attack_time = 1399618395

latency_total = 0.0
latency_num = 0

max_latency = 0
min_latency = 100

lines = open('out', "r").readlines()

for line in lines:
	if line[0] == '#':
		latency, time = line[1:].strip().split(' ')
		if float(time) > attack_time:
			if float(latency) > 100:
				print float(latency)
			else:
				if float(latency) > max_latency:
					max_latency = float(latency)
				if float(latency) < min_latency:
					min_latency = float(latency)
				latency_total += float(latency)
				latency_num += 1

print "total latency num : ", latency_num, ", average : ", latency_total/latency_num
print "min : ", min_latency, ", max : ", max_latency
