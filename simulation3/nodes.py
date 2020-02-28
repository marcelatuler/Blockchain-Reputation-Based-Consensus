import datetime as dt
from const import *
from transactions import *
from tables import *
import time
import random
import rsa
from scipy.stats import gennorm, dgamma, burr, norm
import bloom_filter 
import datetime as date
import json
from block import * 

class Node():

    public_key = None
    private_key = None  # Private
    timestamp = None  # Data de ingresso [data da assinatura do node confiavel]
    #trust_table = {}
    topology = None
    transaction = None
    born_step = 0


    def __init__(self, topology=None,is_miner=False,born_step=0):
        self.topology = topology
        self.is_miner = is_miner
        self.transaction_emiss_flow = []
        self.block_miner_flow = []
        self.born_step = born_step
        self.trust_table = {}
        self.will_check = -1
        self.will_check_control = -1


    
    def do_step(self,step):

        if (step == self.will_check):
            if(self.topology.generated_block[0].owner_public_key in self.trust_table.keys()):
                if(self.topology.generated_block[0].is_malicious):
                    self.trust_table[self.topology.generated_block[0].owner_public_key] = self.trust_table[self.topology.generated_block[0].owner_public_key] - 1
                    if(self.trust_table[self.topology.generated_block[0].owner_public_key] < limiar):
                        new_transac = Transaction(4,step)
                        new_transac.target_public_key = self.topology.generated_block[0].owner_public_key
                        new_transac.origin_public_key = self.public_key.n
                        data = {}
                        data[self.topology.id_exp_trans] = []
                        data[self.topology.id_exp_trans].append({
                        	"transac_type" : new_transac.transaction_type,
                        	"born_step" : new_transac.born_step,
                        	"target_public_key" : new_transac.target_public_key,
                        	"origin_public_key" : new_transac.origin_public_key
                        	})
                        self.topology.exp_transacts_json.append(data)
                        self.topology.exp_transacts.append(new_transac)
                else:
                    self.trust_table[self.topology.generated_block[0].owner_public_key] = self.trust_table[self.topology.generated_block[0].owner_public_key] + 1
                    if(self.trust_table[self.topology.generated_block[0].owner_public_key] > 10):
                        self.trust_table[self.topology.generated_block[0].owner_public_key] = 10
            self.will_check = -1

        if (step == self.will_check_control):
            if(self.topology.generated_block_control[0].owner_public_key in self.trust_table.keys()):
                if(self.topology.generated_block_control[0].is_malicious):
                    self.trust_table[self.topology.generated_block_control[0].owner_public_key] = self.trust_table[self.topology.generated_block_control[0].owner_public_key] - 1
                    if(self.trust_table[self.topology.generated_block_control[0].owner_public_key] < limiar):
                        new_transac = Transaction(4,step)
                        new_transac.target_public_key = self.topology.generated_block_control[0].owner_public_key
                        new_transac.origin_public_key = self.public_key.n
                        data = {}
                        data[self.topology.id_exp_trans] = []
                        data[self.topology.id_exp_trans].append({
                        	"transac_type" : new_transac.transaction_type,
                        	"born_step" : new_transac.born_step,
                        	"target_public_key" : new_transac.target_public_key,
                        	"origin_public_key" : new_transac.origin_public_key
                        	})
                        self.topology.exp_transacts_json.append(data)
                        self.topology.exp_transacts.append(new_transac)
                else:
                    self.trust_table[self.topology.generated_block_control[0].owner_public_key] = self.trust_table[self.topology.generated_block_control[0].owner_public_key] + 1
                    if(self.trust_table[self.topology.generated_block_control[0].owner_public_key] > 10):
                        self.trust_table[self.topology.generated_block_control[0].owner_public_key] = 10
            self.will_check_control = -1
            
        return

    def set_will_check(self,step):
        self.will_check = step + random.randint(1,100)
        #print("will check step",self.will_check)
        return

    def set_will_check_control(self,step):
        self.will_check_control = step + random.randint(1,100)
        #print("will check control = ",self.will_check_control)
        return

    def make_emiss_flow(self,max_steps):
        step = 0
        while step <= max_steps: 
                time_emiss = gennorm.rvs(2.786, 0.371, 0.143, size=1, random_state=None)*10000
                time_emiss = int(round(time_emiss[0]))
                step += time_emiss
                self.transaction_emiss_flow.append(step)
        return

    def make_block_miner_flow(self,max_steps):
        step = 0
        while step <= max_steps:
            time_block = dgamma.rvs(2.0000170661444634, 5.4611854838492295, 0.8244588748930897)
            time_block = int(round(time_block)) * 1000
            step += time_block
            self.block_miner_flow.append(step)
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

    def check_bloom_filter(self,bf_public_key,is_malicious=False):
        bf = bloom_filter.BloomFilter(bf_public_key,k,int(self.number_of_nodes()*prob))

    def __str__(self):
        return "Pub:{}\nPriv:{}".format(self.public_key.n, self.private_key)


class Miner(Node):

    miner_timestamp = None  # None Timestamp
    is_malicious = None # is Malicious or not

    def __init__(self, topology=None,is_miner=False,is_malicious=False):
        Node.__init__(self,is_miner=is_miner)
        self.topology = topology
        self.is_malicious = is_malicious

    def set_private_key(self, private_key):
        self.private_key = private_key

    def make_blocks(self):
        pass

    def set_miner_timestamp(self):
        self.miner_timestamp = dt.datetime.now()

    def get_dict(self):
        data = self.__dict__
        return data

    def do_miner_step(self,step):
    	if(step in self.topology.new_blocks_flow_control):
	        if(len(self.topology.exp_transacts) > 0):
	        	if(self.topology.miners[self.topology.vez2] == self):
		            block = Block(self.public_key.n)
		            block.owner_public_key = self.public_key.n
		            if(self.is_malicious):
		                prob = random.random() * 100
		                if(block_malicious_rate > prob):
		                    block.is_malicious = True
		                else:
		                    for trans in self.topology.exp_transacts:
		                        block.transactions.append(trans)
		                        self.topology.exp_transacts_validated.append(trans)               
		                    self.topology.exp_transacts = []

		                    data = {}
		                    for trans in self.topology.final_exp_trans:
		                    	block.transactions.append(trans)
		                    	self.topology.final_exp_trans.remove(trans)
		                    	for miner in self.topology.miners:
                        			if(miner.public_key.n == trans.target_public_key):
                        				#print(len(self.topology.miners))
                        				self.topology.miners.remove(miner)
                        				self.topology.everything.remove(miner)
	                        			data[str(miner.public_key.n)] = []
	                        			data[str(miner.public_key.n)].append({
	                        				"transac_type" : trans.transaction_type,
	                        				"valid_step" : step,
	                        				"born_step" : trans.born_step,
	                        				"target_public_key" : trans.target_public_key,
	                        				"origin_public_key" : trans.origin_public_key 
	                        				})
                        				self.topology.final_exp_transacts_json.append(data)

                        			if(self.topology.vez > len(self.topology.miners)-1):
                        				self.topology.vez = len(self.topology.miners)-1
                        			if(self.topology.vez2 > len(self.topology.miners)-1):
                        				self.topology.vez2 = len(self.topology.miners)-1


		                self.topology.generated_block_control.append(block)
		                for node in self.topology.everything:
		                    node.set_will_check_control(step)
		            else:
		                for trans in self.topology.exp_transacts:
		                    block.transactions.append(trans)
		                    self.topology.exp_transacts_validated.append(trans)               
		                    self.topology.exp_transacts = []

		                data = {}
		                for trans in self.topology.final_exp_trans:
		                    	block.transactions.append(trans)
		                    	self.topology.final_exp_trans.remove(trans)
		                    	for miner in self.topology.miners:
                        			if(miner.public_key.n == trans.target_public_key):
                        				self.topology.miners.remove(miner)
                        				self.topology.everything.remove(miner)
                        				data[str(miner.public_key.n)] = []
	                        			data[str(miner.public_key.n)].append({
	                        				"transac_type" : trans.transaction_type,
	                        				"valid_step" : step,
	                        				"born_step" : trans.born_step,
	                        				"target_public_key" : trans.target_public_key,
	                        				"origin_public_key" : trans.origin_public_key	 
	                        				})
                        				self.topology.final_exp_transacts_json.append(data)
                        			if(self.topology.vez > len(self.topology.miners)-1):
                        				self.topology.vez = len(self.topology.miners)-1
                        			if(self.topology.vez2 > len(self.topology.miners)-1):
                        				self.topology.vez2 = len(self.topology.miners)-1

		                self.topology.generated_block_control.append(block)
		                for node in self.topology.everything:
		                    node.set_will_check_control(step)

		            block_data = {}
		            array_of_transacs = []
		            block_data[self.topology.id_block_control] = []
		            for trans in block.transactions:
		            	transac = {}
		            	transac[self.topology.trans_in_blocks_id] = []
		            	transac[self.topology.trans_in_blocks_id].append({
		            		"transac_type" : trans.transaction_type,
	                        "valid_step" : step,
	                        "born_step" : trans.born_step,
	                        "target_public_key" : trans.target_public_key,
	                        "origin_public_key" : trans.origin_public_key
		            		})
		            	self.topology.trans_in_blocks_id += 1
		            	array_of_transacs.append(transac)
		            block_data[self.topology.id_block_control].append({
		            	"miner_step" : step,
		            	"miner_pub_key" : self.public_key.n,
		            	"transactions" : array_of_transacs
		            	})
		            self.topology.id_block_control += 1
		            self.topology.blocks_from_controlbc_json.append(block_data)


		            if(self.topology.vez2 == (len(self.topology.miners)-1)):
		            	self.topology.vez2 == 0
		            else:
		            	self.topology.vez2 += 1

class Judge(Node):

    def make_transactions_ejection_solicitation(self):
        pass

    def make_ejections(self):
        pass


if __name__ == "__main__":
    node = Node()
    node.make_keys()
    print(node)