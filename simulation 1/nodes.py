import datetime as dt
from const import *
from transactions import *
from tables import *
import time
import random
import rsa
from scipy.stats import gennorm, dgamma, burr, norm

import datetime as date
import json
import sys


# Nodes for the topology

class Node():

    public_key = None # public key generated with rsa
    private_key = None # private key generated with rsa
    timestamp = None  
    trust_table = {} # dict with the keys of miners that i'm judging
    topology = None 
    transaction = None 
    will_validate = 0 # step when will be validated the current transaction

    def __init__(self, topology=None):
        self.topology = topology
        self.transaction_emiss_flow = []
        self.block_miner_flow = []
    
    def do_step(self,step,close_block=False):
        if step in self.transaction_emiss_flow:

        	# if step is in transaction emiss flow, it will be created a new transaction and added to the pool
        	# to be validated
            new_transaction = Transaction(1,step)
            new_transaction.sign_transaction(self,self.topology.id)
            self.topology.transactions.append(new_transaction)
            data = {}
            data[str(self.topology.id)] = []
            data[str(self.topology.id)].append({
                "transaction_type" : new_transaction.transaction_type,
                "step" : step,
                "public_key" : self.public_key.n,
                "signature": str(new_transaction.origin_signature)
                })
            self.topology.emiss_json.append(data)
            self.topology.id += 1                

        if(self.transaction == None):

        	# when the node is not validating any transaction, he checks if there is any transaction on the pool to be validated
        	# then he takes one ( the oldest one ), and starts the validation
        	# generates validation time with burr, parameters come from Multichain
            if(len(self.topology.transactions) > 0):
                self.transaction = self.topology.transactions[0]
                self.topology.transactions.pop(0)
                time_to_validate = burr.rvs(19.207726887411624, 1.0485858296333794, -0.1563851244724221, 9.799614489119339)
                self.will_validate = step + int(round(time_to_validate))
        elif(step == self.will_validate):

        	# signs the transaction and adds to the validated_transactions pool, to be mined
            self.transaction.sign_miner_trust(self,step)
            data = {}
            data[self.transaction.identify] = []
            data[self.transaction.identify].append({
                "origin_public_key" : self.transaction.origin_public_key.n,
                "origin_signature" : str(self.transaction.origin_signature),
                "transaction_type" : self.transaction.transaction_type,
                "born_step" : self.transaction.born_step,
                "validation_public_key" : self.transaction.validation_public_key,
                "validation_signature" : str(self.transaction.validation_signature),
                "validation_step" : self.transaction.validation_step
                })
            self.topology.validate_json.append(data)
            self.topology.validated_transactions.append(self.transaction)
            self.transaction = None


    def make_emiss_flow_EMR(self,max_steps):
        step = 0
        # emiss flow
        # current time mirror the values from EMR application
        while step <= max_steps: 
                time_emiss = random.randint(420000,780000)
                step += time_emiss
                self.transaction_emiss_flow.append(step)
        return

    def make_emiss_flow(self,max_steps):
        step = 0
    	# emiss flow
    	# current time morror the values from bitcoin transactions 
        while step <= max_steps: 
				time_emiss = gennorm.rvs(2.786, 0.371, 0.143, size=1, random_state=None)*10000
                time_emiss = int(round(time_emiss[0]))
                step += time_emiss
                self.transaction_emiss_flow.append(step)
        return




    def make_keys(self):
        (self.public_key, self.private_key) = rsa.newkeys(KEYSIZE)

    def get_private_key(self):
        return self.private_key

    def get_dict(self):
        data = self.__dict__
        return data

    def make_ingress_transactions(self):
        self.transaction = Ingress()
        self.transaction.sign_transactions(self)

    def set_timestamp(self):
        self.timestamp = dt.datetime.now()


    def update_tables(self):
        pass

    def __str__(self):
        return "Pub:{}\nPriv:{}".format(self.public_key.n, self.private_key)


# Miner for the topology

class Miner(Node):

    miner_timestamp = None  # None Timestamp

    def __init__(self, topology=None):
        Node.__init__(self)
        self.topology = topology
        self.set_timestamp()

    def do_miner_step(self,step):
    	# Closes block if there are validated_transactions and if is his time to do it
    	if(len(self.topology.validated_transactions) > 0):
	                if(self.topology.miners[self.topology.vez] == self):
	                    array = []
	                    array.append(self.public_key.n)
	                    array.append(step)
	                    validated_transactions_array = []
	                    transac = {}

	                    for transaction in self.topology.validated_transactions:
	                        array.append(transaction.identify)
	                        array.append(transaction.origin_public_key.n)
	                        array.append(transaction.origin_signature)
	                        array.append(transaction.transaction_type)
	                        array.append(transaction.born_step)
	                        array.append(transaction.validation_public_key)
	                        array.append(str(transaction.validation_signature))
	                        array.append(transaction.validation_step)

	                        transac["id"] = transaction.identify
	                        transac["pub_key_origin"] = transaction.origin_public_key.n
	                        transac["sign_origin"] = str(transaction.origin_signature)
	                        transac["transac_type"] = transaction.transaction_type
	                        transac["born_step"] = transaction.born_step
	                        transac["pub_key_valid"] =transaction.validation_public_key
	                        transac["sign_valid"] = str(transaction.validation_signature)
	                        transac["valid_step"] = transaction.validation_step

	                        validated_transactions_array.append(transac)



	                    hash_block = rsa.compute_hash(repr(array).encode('utf-8'),'SHA-1')
	                    content = "{}".format(hash_block)
	                    signature = rsa.sign(content.encode("utf-8"), self.get_private_key(), 'SHA-1')

	                    data = {}
	                    data[str(hash_block)] = []
	                    data[str(hash_block)].append({
	                        "miner_public_key" : self.public_key.n,
	                        "miner_step" : step,
	                        "miner_signature" : str(signature),
	                        "transactions" : validated_transactions_array
	                        })
	                    self.topology.block_mined_json.append(data)
	                    self.topology.validated_transactions = []

    def set_private_key(self, private_key):
        self.private_key = private_key

    def make_blocks(self):
        pass

    def set_miner_timestamp(self):
        self.miner_timestamp = dt.datetime.now()

    def get_dict(self):
        data = self.__dict__
        return data


class Judge(Node):

    def make_transactions_ejection_solicitation(self):
        pass

    def make_ejections(self):
        pass


if __name__ == "__main__":
    node = Node()
    node.make_keys()