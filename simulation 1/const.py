# constants for our simulation

KEYSIZE = 512
TRANSACTIONS = {
    "ingress": 0,
    "miner": 1,
    "request_expulsion": 2,
    "expulsion": 3,
}
BLOOM_MAX_ELEMENTS = 5  #number of elements that the filter holds (deve ser testado)
MINER_SLEEP_SIGNATURE_RANGE = 1

number_of_nodes = 100
miners_rate = 10