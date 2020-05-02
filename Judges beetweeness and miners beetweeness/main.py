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
import networkx as nx
import matplotlib.pyplot as plt
from random import randint
import copy


#   reference of RSA KEYS vrauu
#   https://stuvel.eu/python-rsa-doc/usage.html#generating-keys

#   bloom filter
#   https://media.readthedocs.org/pdf/pybloomfiltermmap3/latest/pybloomfiltermmap3.pdf


class Topology(Graph):

    insertion_queue = []

    # new atributo // migrar para classe constantes

    def __init__(self, initial_nodes=0, ind=None):
        Graph.__init__(self)

        self.removed = []

        self.G = nx.Graph()
        self.K = nx.Graph()        
        
        self.member_nodes = self.make_nodes2(initial_nodes,malicious_rate, self)
        self.miners = []

        random.shuffle(self.member_nodes)

        array_to_del = []

        for i in range(initial_nodes//miners_rate):
            node = self.member_nodes[i]
            if(self.member_nodes[i].is_malicious):
                if i < 23:
                    miner = Miner(self,is_miner=True,is_malicious=True, min_int=i, money=randint(1,200))
                else:
                    miner = Miner(self,is_miner=True,is_malicious=True, min_int=i, money=randint(100000,5000000))
            else:
                if i < 23:
                    miner = Miner(self,is_miner=True,is_malicious=False, min_int=i, money=randint(1,200))
                else:
                    miner = Miner(self,is_miner=True,is_malicious=False, min_int=i, money=randint(100000,5000000))

            miner.set_private_key(node.get_private_key())
            miner.public_key = node.public_key



            self.miners.append(miner)
            array_to_del.append(node)
        
        #print("Minners added!")
        self.G.add_nodes_from(self.miners)

        for node in array_to_del:
            self.member_nodes.remove(node)

        self.everything = []

        for miner in self.miners:
            self.everything.append(miner)
         
        #for node in self.member_nodes:
        #    self.everything.append(node)

        random.shuffle(self.everything)

        array = []
        array2 = []

        count = 0

        # bloomfilter generate
        for miner in self.miners:
            # print(str(miner.public_key.n))
            array = bin(int((str(miner.public_key.n))))[2:]
            bf = bloom_filter.BloomFilter(array,k,int(self.number_of_nodes()*prob))
            if(miner.is_malicious):
            	count +=1

            true = 0
            ##  
            for node in self.everything:
                if(miner != node):
                    if(bf.check(str(node.public_key.n))):
                        node.trust_table[miner.public_key.n] = entrance_grade
                        true += 1
            array2.append(true)



        # Beetweeness of judges
        """
        self.K.add_nodes_from(self.everything)
        # Keys graph generating
        for i in range(len(self.everything)):
            for j in range(i+1, len(self.everything)):
                for key in self.everything[i].trust_table.keys():
                    if key in self.everything[j].trust_table.keys():
                        self.K.add_edge(self.everything[i], self.everything[j], weight=1)
                        break
        
        bc = nx.betweenness_centrality(self.K, normalized=False)
        bcs = []

        for node in self.everything:
            bcs.append(bc[node])

        #nx.draw(self.K, cmap=plt.get_cmap('jet'))
        #plt.show()
        
        with open("bc_judges/bc_judges_500-{}.json".format(ind),"w") as outfile:
            json.dump(bcs ,outfile)
        """
        
        
        self.insertion_queue = []  # First element = (is node signing), second = Node()

        # transactions
        self.identify = 0
        self.transactions = []
        self.validated_transactions = []

        self.miner_numbers = len(self.miners)
        self.all_nodes = self.number_of_nodes()

        # fluxo de fechamento de bloco
        self.block_closed_flow = []

        # Variaveis relacionadas ao fluxo da blockchain
        self.new_blocks_flow = []
        self.bc_turn = 1
        self.id_block_bc = 0
        self.blocks_from_blockchain_json = []


        # vez de qual minerador fechar um bloco na blockchain de controle
        self.bc_control_turn = self.calculate_bc_turn(0)
        #print("first one calculated")
        #sys.exit()

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
        self.id_exp_trans = 0
        self.id_block_control = 0
        self.trans_in_blocks_id = 0


        # transações de expulsão
        self.exp_transacts = {}

        for miner in self.miners:
        	self.exp_transacts[miner.public_key.n] = [0,[],False,[]]


        # transações de expulsão validadas
        self.exp_transacts_validated = []

        # transações 
        self.final_exp_trans = {}

        # blocos da blockchain
        self.generated_block = Block()

        # blocks de controle
        self.generated_block_control = Block()


        # arquivos.json
        self.blocks_from_blockchain_json = []
        self.exp_transacts_json = []
        self.final_exp_transacts_json = []
        self.blocks_from_controlbc_json = []


        self.expss = 0

        self.data = {}
        self.iden = 0
    
    def calculate_bc_turn(self, step):
        tmp_node = self.miners[0].money * self.miners[0].waiting
        resp_id = 0
        for i in range(1,len(self.miners)):
            if (self.miners[i].money * self.miners[i].waiting) > tmp_node:
                tmp_node = self.miners[i].money * self.miners[i].waiting
                resp_id = i
        
        #print(self.everything[resp_id].money)
        #print(resp_id)

        for j in range(0,len(self.miners)):
            self.miners[j].waiting += step
        
        self.miners[resp_id].waiting = 1

        #print(self.miners[0].waiting * self.miners[0].money)
        #print(self.miners[resp_id].waiting * self.miners[resp_id].money)
        return resp_id


    def insert_node(self, node):
        node.topology = self
        self.insertion_queue.append(node)

    def make_keys(self):
        return rsa.newkeys(512)

    def make_blocks_flow(self,max_steps):
    	step = 0

    	while step <= max_steps:
    		time_block = dgamma.rvs(2.0000170661444634, 5.4611854838492295, 0.8244588748930897)
    		if(time_block > 1):
    			time_block = int(round(time_block)) * 1000
    			step += time_block
    			self.new_blocks_flow.append(step)
    	return 

    def make_blocks_flow_control(self,max_steps):
        step = 0
        while step <= max_steps:
            time_block = dgamma.rvs(2.0000170661444634, 5.4611854838492295, 0.8244588748930897)
            if(time_block > 1):
            	time_block = int(round(time_block)) * 1000
            	step += time_block
            	self.new_blocks_flow_control.append(step)
        return 


if __name__ == "__main__":
    for i in range(1,31):
        print("Starting simulation {}".format(i))
        topology = Topology(initial_nodes=init_nodes)
        reset_block = -1
        reset_block_control = -1
        miners_removed = 0
        old = None

        # Fluxo de geração de blocos, blockchain e blockchain controle
        topology.make_blocks_flow(simulation_steps)
        topology.make_blocks_flow_control(simulation_steps)

        ind = topology.calculate_bc_turn(0)
        #print(ind)
        miner = topology.miners[ind]
        #print(miner.min_int)

        for step in range(simulation_steps):
            if(step in topology.new_blocks_flow):
                #print(topology.bc_turn)
                #if(topology.bc_turn > len(topology.miners)-1):
                    #topology.bc_turn = 0

                
                new_ind = topology.calculate_bc_turn(step)

                if old is not None:
                    topology.G.add_edge(topology.miners[new_ind], topology.miners[old], weight=1)
                    #print("edge addeed between {} e {}".format(new_ind, old))
                
                old = new_ind

                miner = topology.miners[ind]
                
                if(miner.is_malicious):
                    block = Block(key=miner.public_key.n)
                    prob = random.random() * 100
                    if(block_malicious_rate > prob):
                        block.is_malicious = True
                        miner.money = randint(1,1000)
                        miner.grades_flush.append(-1)
                    else:
                        miner.grades_flush.append(1)
                else:
                    block = Block(key=miner.public_key.n)
                    miner.grades_flush.append(1)
                
                #print("Block closed")

                #for node in topology.everything:
                    #node.check_trust_table(block,step)

                data = {}
                data[topology.id_block_bc] = []
                data[topology.id_block_bc].append({
                    "origin_step" : step,
                    "miner_pub_key" : miner.public_key.n,
                    "is_malicious" : block.is_malicious
                    })

                topology.blocks_from_blockchain_json.append(data)
                topology.id_block_bc += 1
                topology.generated_block = block
                reset_block = step + 101

                #if(topology.bc_turn >= len(topology.miners)-1):
                #    topology.bc_turn = 0
                #else:
                #    topology.bc_turn += 1

            if(step in topology.new_blocks_flow_control):
                for miner in topology.miners:
                    miner.do_miner_step(step)
                if(topology.bc_control_turn >= len(topology.miners)-1):
                    topology.bc_control_turn = 1
                else:
                    topology.bc_control_turn += 1

        bc = nx.betweenness_centrality(topology.G, normalized=False)
        
        bcs = []

        #all_nodes = []
        #for nodes in topology.miners:
        #    all_nodes.append(nodes)
        #for nodes in topology.removed:
            #all_nodes.append(nodes)
        
        #print("miners removed = {}, all nodes = {}".format(len(topology.removed), len(all_nodes)))

        for node in topology.miners:
            bcs.append(bc[node])
        
        with open("PoS/POS-100-{}.json".format(i),"w") as outfile:
            json.dump(bcs ,outfile)
        

        '''
        with open("blockchain_blocks.json","w") as outfile:
            json.dump(topology.blocks_from_blockchain_json,outfile)

        with open("exp_transacts.json","w") as outfile:
            json.dump(topology.exp_transacts_json,outfile)  

        with open("blocks_from_control.json","w") as outfile:
            json.dump(topology.blocks_from_controlbc_json,outfile)      

        for miner in topology.miners:
            topology.data[topology.iden] = [miner.grades_flush,miner.is_malicious]
            topology.iden += 1

        with open("miners_grades.json","w") as outfile:
            json.dump(topology.data,outfile)
        with open("final_exp_transacts.json","w") as outfile:
            json.dump(main.final_exp_transacts_json,outfile)
        '''