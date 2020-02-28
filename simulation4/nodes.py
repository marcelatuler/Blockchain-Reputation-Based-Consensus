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
import sys

class Node():

    is_malicious = None
    public_key = None
    private_key = None  # Private
    timestamp = None  # Data de ingresso [data da assinatura do node confiavel]
    #trust_table = {}
    topology = None
    transaction = None
    born_step = 0


    def __init__(self, topology=None,is_miner=False,born_step=0,is_malicious=False):
        self.topology = topology
        self.is_miner = is_miner
        self.transaction_emiss_flow = []
        self.block_miner_flow = []
        self.born_step = born_step
        self.trust_table = {}
        self.will_check = -1
        self.will_check_control = -1


    
    def do_step(self,step):
        pass
            

    def check_trust_table(self,block,step):
        if(block.owner_public_key in self.trust_table.keys()):
            if(block.is_malicious):
                self.trust_table[block.owner_public_key] = self.trust_table[block.owner_public_key] - 1
                if(self.trust_table[block.owner_public_key] == (limiar-1)):
                    born_step = step + random.randint(0,101)
                    time_to_validate = burr.rvs(19.207726887411624, 1.0485858296333794, -0.1563851244724221, 9.799614489119339)
                    valid_step = born_step + int(round(time_to_validate))
                    new_transac = Transaction(4,born_step)
                    new_transac.target_public_key = block.owner_public_key
                    new_transac.origin_public_key = self.public_key.n
                    data = {}
                    data[self.topology.id_exp_trans] = []
                    data[self.topology.id_exp_trans].append({
                        "transac_type" : new_transac.transaction_type,
                        "born_step" : born_step,
                        "valid_step" : valid_step,
                        "target_public_key" : new_transac.target_public_key,
                        "origin_public_key" : new_transac.origin_public_key
                        })

                    content = "{}".format(data)
                    signature = rsa.sign(content.encode('utf-8'), self.private_key, 'SHA-1')

                    self.topology.exp_transacts_json.append(data)
                    self.topology.exp_transacts[block.owner_public_key][0] += 1
                    self.topology.exp_transacts[block.owner_public_key][1].append(new_transac)
                    self.topology.exp_transacts[block.owner_public_key][3].append(str(signature))
                    self.topology.id_exp_trans += 1
            else:
                self.trust_table[block.owner_public_key] = self.trust_table[block.owner_public_key] + 1
                if(self.trust_table[block.owner_public_key] >= 10):
                    self.trust_table[block.owner_public_key] = 10

            if(self.topology.bc_control_turn > len(self.topology.miners)-1):
                self.topology.bc_control_turn = 0

    def make_emiss_flow(self,max_steps):
        step = 0
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

    def check_bloom_filter(self,bf_public_key,is_malicious=False):
        bf = bloom_filter.BloomFilter(bf_public_key,k,int(self.number_of_nodes()*prob))

    def __str__(self):
        return "Pub:{}\nPriv:{}".format(self.public_key.n, self.private_key)


class Miner(Node):

    miner_timestamp = None  # None Timestamp
    is_malicious = None # is Malicious or not
    grades_flush = []

    def __init__(self, topology=None,is_miner=False,is_malicious=False):
        Node.__init__(self,is_miner=is_miner)
        self.topology = topology
        self.is_malicious = is_malicious
        self.grades_flush = []

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
        if(self.topology.miners[self.topology.bc_control_turn] == self):
            block = Block(key=self.public_key.n)

            if(self.is_malicious):
                prob = random.random() * 100
                if(block_malicious_rate > prob):
                    block.is_malicious = True
                    self.grades_flush.append(-1)
                    for node in self.topology.everything:
                        node.check_trust_table
                    
                else:
                    self.grades_flush.append(1)
                    if(len(self.topology.final_exp_trans) > 0):
                        for k in self.topology.final_exp_trans.keys():
                            if self.topology.final_exp_trans[k][0] == False:
                                for miner in self.topology.miners:
                                    if(k == miner.public_key.n):
                                        self.topology.data[self.topology.iden] = [miner.grades_flush,miner.is_malicious]
                                        self.topology.iden += 1
                                        self.topology.miners.remove(miner)
                                        self.topology.everything.remove(miner)
                                self.topology.final_exp_trans[k][3].signatures = self.topology.final_exp_trans[k][2]
                                self.topology.final_exp_trans[k][0] = True
                                block.transactions.append(self.topology.final_exp_trans[k][3])
                                self.topology.expss +=1

                            

                    for key in self.topology.exp_transacts.keys():
                        if(self.topology.exp_transacts[key][2] == False and (len(self.topology.exp_transacts[key][1]) > (judges//2 + 1))):
                            self.topology.exp_transacts[key][2] = True
                            born_step = step + random.randint(0,101)
                            time_to_validate = burr.rvs(19.207726887411624, 1.0485858296333794, -0.1563851244724221, 9.799614489119339)
                            valid_step = born_step + int(round(time_to_validate))
                            new_transac = Transaction(5,born_step)
                            new_transac.target_public_key = key
                            new_transac.origin_public_key = self.topology.exp_transacts[key][1][0].origin_public_key
                            new_transac.validation_step = valid_step
                            self.topology.final_exp_trans[key] = [False,self.topology.exp_transacts[key][1],self.topology.exp_transacts[key][3],new_transac]

            else:
                self.grades_flush.append(1)

                if(len(self.topology.final_exp_trans) > 0):
                    for k in self.topology.final_exp_trans.keys():
                        if self.topology.final_exp_trans[k][0] == False:
                            for miner in self.topology.miners:
                                if(k == miner.public_key.n):
                                    self.topology.data[self.topology.iden] = [miner.grades_flush,miner.is_malicious]
                                    self.topology.iden += 1
                                    self.topology.miners.remove(miner)
                                    self.topology.everything.remove(miner)
                            self.topology.final_exp_trans[k][3].signatures = self.topology.final_exp_trans[k][2]
                            self.topology.final_exp_trans[k][0] = True
                            block.transactions.append(self.topology.final_exp_trans[k][3])
                            self.topology.expss +=1

                for key in self.topology.exp_transacts.keys():
                    if(self.topology.exp_transacts[key][2] == False and (len(self.topology.exp_transacts[key][1]) > (judges//2 + 1))):
                        self.topology.exp_transacts[key][2] = True
                        born_step = step + random.randint(0,101)
                        time_to_validate = burr.rvs(19.207726887411624, 1.0485858296333794, -0.1563851244724221, 9.799614489119339)
                        valid_step = born_step + int(round(time_to_validate))
                        new_transac = Transaction(5,born_step)
                        new_transac.target_public_key = key
                        new_transac.origin_public_key = self.topology.exp_transacts[key][1][0].origin_public_key
                        new_transac.validation_step = valid_step
                        self.topology.final_exp_trans[key] = [False,self.topology.exp_transacts[key][1],self.topology.exp_transacts[key][3],new_transac]

            block_data = {}
            array_of_transacs = []
            block_data[self.topology.id_block_control] = []

            if(len(block.transactions) > 0):
                for trans in block.transactions:
                    transac = {}
                    transac[self.topology.trans_in_blocks_id] = []
                    transac[self.topology.trans_in_blocks_id].append({
                        "transac_type" : trans.transaction_type,
                        "miner_step" : step,
                        "valid_step" : trans.validation_step,
                        "born_step" : trans.born_step,
                        "target_public_key" : trans.target_public_key,
                        "origin_public_key" : trans.origin_public_key,
                        "signatures" : trans.signatures
                    })
                    self.topology.trans_in_blocks_id += 1
                    array_of_transacs.append(transac)
            block_data[self.topology.id_block_control].append({
                "miner_step" : step,
                "miner_pub_key" : self.public_key.n,
                "transactions" : array_of_transacs,
                "is_malicious" : block.is_malicious
            })
            self.topology.id_block_control += 1
            self.topology.blocks_from_controlbc_json.append(block_data)


            if(self.topology.bc_turn > len(self.topology.miners)-1):
                self.topology.bc_turn = 0



class Judge(Node):

    def make_transactions_ejection_solicitation(self):
        pass

    def make_ejections(self):
        pass


if __name__ == "__main__":
    node = Node()
    node.make_keys()
    print(node)