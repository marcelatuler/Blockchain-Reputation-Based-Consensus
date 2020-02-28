KEYSIZE = 512
TRANSACTIONS = {
    "ingress": 0,
    "miner": 1,
    "request_expulsion": 2,
    "expulsion": 3,
}
BLOOM_MAX_ELEMENTS = 5  #number of elements that the filter holds (deve ser testado)
MINER_SLEEP_SIGNATURE_RANGE = 1


#bloomfilter
items_count = 5

##############################

# first grade to attribute 
first_grade = 6 
limiar = 6 #6 : {6,8,media}, 7:{7,9,media}, 8{8,10,media}

# taxa de mineradores
miners_rate = 3 
# taxa de mineradores que serão maliciosos
malicious_rate = 2
# taxa de blocos maliciosos gerados por mineradores maliciosos in percent [1 - 100]
block_malicious_rate = 100 # 80 %



# bloom filter
k = 1	# number of hashes # 2: 25 %, 3:12.5 %
prob = 0.5

# percent of all numbers judging
judges = 50 # 25, 12.5

simulation_steps = 3600000

# notes
entrance_grade = 6.0
threshold_grade = 6.0 # 6 to 8

init_nodes = 100