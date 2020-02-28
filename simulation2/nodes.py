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

class Node():

    public_key = None
    private_key = None  # Private
    timestamp = None  # Data de ingresso [data da assinatura do node confiavel]
    trust_table = {}
    topology = None
    transaction = None
    will_validate = 0
    born_step = 0


    def __init__(self, topology=None,is_miner=False,born_step=0):
        self.topology = topology
        self.is_miner = is_miner
        self.transaction_emiss_flow = []
        self.block_miner_flow = []
        self.born_step = born_step

    
    def do_step(self,step,close_block=False):
        pass

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
        	if(time_block > 1):
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

    def check_bloom_filter(self,bf_public_key):
        bf = bloom_filter.BloomFilter(5,0.1)
        bf.add(str(bf_public_key.n))
        if(bf.check(str(self.public_key))):
            print("sou juiz desse cara")
            self.trust_table[bf_public_key.n] = 6.0

    def __str__(self):
        return "Pub:{}\nPriv:{}".format(self.public_key.n, self.private_key)


class Miner(Node):

    miner_timestamp = None  # None Timestamp

    def __init__(self, topology=None,is_miner=False):
        Node.__init__(self,is_miner=is_miner)
        self.topology = topology

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
        if(self.transaction == None):
            if(len(self.topology.transactions) > 0 ):
                self.transaction = self.topology.transactions[0]
                self.topology.transactions.pop(0)
                time_to_validate = random.randint(6,13)
                self.will_validate = step + time_to_validate
        elif(step == self.will_validate):
            self.transaction.validation_step = step
            self.transaction.validation_public_key = self.public_key.n
            if(self.transaction.transaction_type == 2):
                content = "{}{}{}{}{}{}".format(self.transaction.identify,self.transaction.born_step,(self.transaction.born_step+110),
                    self.transaction.origin_public_key,str(self.transaction.origin_signature),self.public_key.n,step)
            if(self.transaction.transaction_type == 3):
                content = "{}{}{}{}{}{}".format(self.transaction.identify,self.transaction.born_step,self.transaction.ingress_step,
                    self.transaction.origin_public_key,str(self.transaction.origin_signature),self.public_key.n,step)

            self.transaction.validation_signature = rsa.sign(content.encode('utf-8'),self.private_key,'SHA-1')
            self.topology.validated_transactions.append(self.transaction)
            self.transaction = None

        if(step in self.block_miner_flow):
            if(self == self.topology.miners[self.topology.vez]):
                if(len(self.topology.validated_transactions) == 0 ):
                    pass
                else:
                    array = []
                    validated_transactions_array = []
                    transac = {}

                    array.append(step)
                    array.append(self.public_key.n)

                    for transaction in self.topology.validated_transactions:
                        if(transaction.transaction_type == 2):
                            array.append(transaction.identify)
                            array.append(transaction.origin_public_key)
                            array.append(str(transaction.origin_signature))
                            array.append(transaction.born_step)
                            array.append((transaction.born_step+110))
                            array.append(transaction.transaction_type)

                            transac["id"] = transaction.identify
                            transac["pub_key_origin"] = str(transaction.origin_public_key)
                            transac["sign_origin"] = str(transaction.origin_signature)
                            transac["transac_type"] = transaction.transaction_type
                            transac["born_step"] = transaction.born_step
                            transac["make_keys_step"] = (transaction.born_step+110)
                            transac["pub_key_valid"] = transaction.validation_public_key
                            transac["sign_valid"] = str(transaction.validation_signature)
                            transac["valid_step"] = transaction.validation_step

                        else:
                            array.append(transaction.identify)
                            array.append(transaction.origin_public_key)
                            array.append(str(transaction.origin_signature))
                            array.append(transaction.born_step)
                            array.append(transaction.ingress_step)
                            array.append(transaction.transaction_type)

                            transac["id"] = transaction.identify
                            transac["pub_key_origin"] = str(transaction.origin_public_key)
                            transac["sign_origin"] = str(transaction.origin_signature)
                            transac["transac_type"] = transaction.transaction_type
                            transac["born_step"] = transaction.born_step
                            transac["ingress_step"] = (transaction.ingress_step)
                            transac["pub_key_valid"] = transaction.validation_public_key
                            transac["sign_valid"] = str(transaction.validation_signature)
                            transac["valid_step"] = transaction.validation_step#self.topology.miners_approved.append(transaction)
                    validated_transactions_array.append(transac)


                    hash_block = rsa.compute_hash(repr(array).encode('utf-8'),'SHA-1')
                    content = "{}".format(hash_block)
                    signature = rsa.sign(content.encode('utf-8'),self.private_key,'SHA-1')

                    data = {}
                    data[str(hash_block)] = []
                    data[str(hash_block)].append({
                        "miner_public_key" : self.public_key.n,
                        "miner_step" : step,
                        "miner_signature" : str(signature),
                        "transactions" : validated_transactions_array
                        })

                    self.topology.block_mined_json.append(data)
                    self.topology.nodes_approved = self.topology.validated_transactions.copy()
                    self.topology.validated_transactions = []


                if(self.topology.vez == len(self.topology.miners)-1):
                    self.topology.vez = 0
                else:
                    self.topology.vez += 1
        return

class Judge(Node):

    def make_transactions_ejection_solicitation(self):
        pass

    def make_ejections(self):
        pass


if __name__ == "__main__":
    node = Node()
    node.make_keys()
    print(node)