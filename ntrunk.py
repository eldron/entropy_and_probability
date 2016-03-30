from __future__ import division
import random
import math

def cal_entropy(N):
	list = []
	for i in range(N):
		list.append(random.randint(0, 255))

	counters = []
	for i in range(256):
		counters.append(list.count(i))

	entropy = float(0)
	for i in counters:
		if i > 0:
			tmp = (i / N) * math.log(i / N, 2)
			entropy += tmp

	return float(float(0) - entropy)

def cal_ntrunk(N):
	values = []
	for i in range(100000):
		values.append(cal_entropy(N))

	return float(sum(values) / 100000)

print cal_ntrunk(65536)

# for i in range(200, 65536):
# 	print cal_ntrunk(i)
