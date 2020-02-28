from nodes import *
from const import *
from transactions import *
from threading import Thread
from topology.graph import Graph
from scipy.stats import dgamma
import os
import json
import rsa
import bloom_filter
import sys
from block import * 

#   reference of RSA KEYS vrauu
#   https://stuvel.eu/python-rsa-doc/usage.html#generating-keys

#   bloom filter
#   https://media.readthedocs.org/pdf/pybloomfiltermmap3/latest/pybloomfiltermmap3.pdf


class Topology(Graph):

    insertion_queue = []

    # new atributo // migrar para classe constantes

    def __init__(self, initial_nodes=0):
        Graph.__init__(self)
        
        self.member_nodes = self.make_nodes(initial_nodes, self)
        self.miners = self.make_miners(self.member_nodes, round(initial_nodes/miners_rate), self, malicious_rate)

        random.shuffle(self.miners)

        self.everything = []

        for miner in self.miners:
            self.everything.append(miner)
        for node in self.member_nodes:
            self.everything.append(node)

        random.shuffle(self.everything)



        array = []
        array2 = []

        for miner in self.miners:
            array = bin(int((str(miner.public_key.n))))[2:]
            bf = bloom_filter.BloomFilter(array,k,int(self.number_of_nodes()*prob))

            true = 0
            ##  
            for node in self.everything:
                if(miner != node):
                    if(bf.check(str(node.public_key.n))):
                        node.trust_table[miner.public_key.n] = entrance_grade
                        true += 1
            array2.append(true)
        

        self.insertion_queue = []  # First element = (is node signing), second = Node()

        # transactions
        self.identify = 0
        self.transactions = []
        self.validated_transactions = []

        self.miner_numbers = len(self.miners)
        self.all_nodes = self.number_of_nodes()

        # fluxo de fechamento de bloco
        self.block_closed_flow = []

        # Vez de qual minerador gerar um bloco na blockchain
        self.vez = 0

        # vez de qual minerador fechar um bloco na blockchain de controle
        self.vez2 = 0

        # flow of new nodes
        # blocos chegada block chain
        self.new_blocks_flow = []
        self.made_key = []

        # blocos de controle
        self.new_blocks_flow_control = []

        # json files
        self.emiss_trans = []
        self.block_mined_json = []

        # new nodes array 
        self.nodes_approved = []
        self.miners_approved = []
        self.keys_tuple = []

        # ids
        self.id_block_bc = 0
        self.id_exp_trans = 0
        self.id_block_control = 0
        self.trans_in_blocks_id = 0


        # transações de expulsão
        self.exp_transacts = []

        # transações de expulsão validadas
        self.exp_transacts_validated = []

        # transações 
        self.final_exp_trans = []

        # blocos da blockchain
        self.generated_block = []

        # blocks de controle
        self.generated_block_control = []


        # arquivos.json
        self.blocks_from_blockchain_json = []
        self.exp_transacts_json = []
        self.final_exp_transacts_json = []
        self.blocks_from_controlbc_json = []


    def insert_node(self, node):
        node.topology = self
        self.insertion_queue.append(node)

    def make_keys(self):
        return rsa.newkeys(512)

    def make_blocks_flow(self,max_steps):
    	step = 0

    	while step <= max_steps:
    		if(time_block > 1):
    			time_block = dgamma.rvs(2.0000170661444634, 5.4611854838492295, 0.8244588748930897)
    			time_block = int(round(time_block)) * 1000
    			step += time_block
    			self.new_blocks_flow.append(step)
    	return 

    def make_blocks_flow_control(self,max_steps):
        step = 0
        while step <= max_steps:
        	if(time_block > 1):
            	time_block = dgamma.rvs(2.0000170661444634, 5.4611854838492295, 0.8244588748930897)
            	time_block = int(round(time_block)) * 1000
            	step += time_block
            	self.new_blocks_flow_control.append(step)
        return 


if __name__ == "__main__":
    main = Topology(initial_nodes=100)
    simulation_steps = 3600000
    reset_block = -1
    reset_block_control = -1
    miners_removed = 0

    # Geração aleatória de blocos da Blockchain
    main.make_blocks_flow(simulation_steps)

    # fechamento de blocos de controle
    main.make_blocks_flow_control(simulation_steps)

    for step in range(simulation_steps):

        if(len(main.exp_transacts_validated) > 0):
            for trans in main.exp_transacts_validated:
                count = 0
                array = []
                for i in range(len(main.exp_transacts_validated)):
                    if(trans.target_public_key == main.exp_transacts_validated[i].target_public_key):
                        count += 1
                        array.append(main.exp_transacts_validated[i])

                if(count > (judges//2) +1 ):
                    new_transac = Transaction(5,step)
                    new_transac.target_public_key = trans.target_public_key
                    new_transac.origin_public_key = trans.origin_public_key
                    main.final_exp_trans.append(new_transac)
                    for item in array:
                        main.exp_transacts_validated.remove(item)

        # chegada de blocos da blockchain e análise de bloco gerado
        if(step in main.new_blocks_flow):
            miner = main.miners[main.vez]
            if(miner.is_malicious):
                for node in main.everything:
                    node.set_will_check(step)
                block = Block(miner.public_key.n)
                prob = random.random() * 100
                if(block_malicious_rate > prob):
                    block.is_malicious = True
                else:
                    pass
            else:
                block = Block(miner.public_key.n)

            for node in main.everything:
                node.set_will_check(step)

            data = {}
            data[main.id_block_bc] = []
            data[main.id_block_bc].append({
                "origin_step" : step,
                "miner_pub_key" : miner.public_key.n,
                "is_malicious" : block.is_malicious
                })

            main.blocks_from_controlbc_json.append(data)
            main.id_block_bc += 1

            main.generated_block.append(block)
            reset_block = step + 101

            if(main.vez >= len(main.miners)-1):
                main.vez = 0
            else:
                main.vez += 1


        # Mineração de blocos na blockchain de controle
        if(step in main.new_blocks_flow_control):
            if(len(main.exp_transacts) > 0):
                main.miners[main.vez2].do_miner_step(step)
                reset_block_control = step + 101

        # do step for everynode every step
        for node in main.everything:
            node.do_step(step)

        for miner in main.miners:
            miner.do_miner_step(step)

        # reset blockchain block array
        if(step == reset_block):
            #print("reset block =",step)
            main.generated_block.pop(0)

        # reset control blockchain block array
        if(step == reset_block_control):
            main.generated_block_control.pop(0)

    with open("blockchain_blocks.json","w") as outfile:
        json.dump(main.blocks_from_controlbc_json,outfile)

    with open("exp_transacts.json","w") as outfile:
        json.dump(main.exp_transacts_json,outfile)        

    with open("final_exp_transacts.json","w") as outfile:
        json.dump(main.final_exp_transacts_json,outfile)

    with open("blocks_from_control.json","w") as outfile:
        json.dump(main.blocks_from_controlbc_json,outfile)