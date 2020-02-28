import json
import sys
import Statistics as stats

media = int(sys.argv[1])//2

number_of_judges = []
number_of_nodes_under_average = 0

for i in range(0,299):
	filename = "judges_per_miner-"+str(i)+".json"
	judges_json = json.load(open(filename,"r"))

	for j in range(len(judges_json)):
		number_of_judges.append(judges_json[j])

for i in range(len(number_of_judges)):
	if(number_of_judges[i] < media):
		number_of_nodes_under_average += 1
print(number_of_judges)
print(number_of_nodes_under_average)

s = stats.Statistics()
media = s.getMean(number_of_judges)
print(media)
errorbar = s.getConfidenceInterval(number_of_judges)
print(errorbar)