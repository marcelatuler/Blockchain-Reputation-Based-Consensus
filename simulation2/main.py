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
        self.miners = self.make_miners(self.member_nodes, round(initial_nodes/miner_ratio), self)

        self.everything = []

        for miner in self.miners:
            self.everything.append(miner)

        for node in self.member_nodes:
            self.everything.append(node)

        self.insertion_queue = []  # First element = (is node signing), second = Node()

        # transactions
        self.identify = 0
        self.transactions = []
        self.validated_transactions = []

        self.miner_numbers = len(self.miners)
        self.all_nodes = self.number_of_nodes()

        # fluxo de fechamento de bloco
        self.block_closed_flow = []

        # vez de qual minerador fechar o bloco
        self.vez = 0

        # flow of new nodes
        self.new_nodes_flow = []
        self.made_key = []

        # json files
        self.emiss_trans = []
        self.block_mined_json = []

        # new nodes array 
        self.nodes_approved = []
        self.miners_approved = []
        self.keys_tuple = []

        self.teste = []

    def insert_node(self, node):
        node.topology = self
        self.insertion_queue.append(node)

    def make_new_node_flow(self,max_steps):
        step = 0
        while step <= max_steps:
            step += 60000 # 1 minuto
            self.new_nodes_flow.append(step)
            self.made_key.append(step+110)

    def make_keys(self):
        return rsa.newkeys(512)



if __name__ == "__main__":
    main = Topology(initial_nodes=10)

    simulation_steps = 3600000
    main.make_new_node_flow(simulation_steps)

    for node in main.nodes():
        if (node.is_miner):
            node.make_block_miner_flow(simulation_steps)

    for step in range(simulation_steps):
        if(len(main.nodes_approved) > 0):
            for transaction in main.nodes_approved:
                for tuples in main.keys_tuple:
                    if(transaction.origin_public_key == tuples[0]):

                        new_node = Node(topology=main,is_miner=False,born_step=step)
                        new_node.public_key = transaction.origin_public_key
                        new_node.private_key = tuples[1]
                        #for node in main.miners:
                        #    new_node.check_bloom_filter(node.public_key)
                        main.add_node(new_node)
                        main.member_nodes.append(new_node)
                        main.everything.append(new_node)
                        main.keys_tuple.remove(tuples)

                        if(round(main.number_of_nodes()/miner_ratio) > main.miner_numbers):
                            new_transaction = Transaction(3,step)
                            new_transaction.identify = main.identify
                            new_transaction.ingress_step = main.member_nodes[0].born_step
                            new_transaction.origin_public_key = main.member_nodes[0].public_key
                            content = "{}{}{}{}{}".format(new_transaction.identify,new_transaction.born_step,
                                new_transaction.transaction_type,public_key.n,new_transaction.ingress_step)
                            new_transaction.origin_signature = rsa.sign(content.encode('utf-8'), private_key, 'SHA-1')
                            main.identify += 1
                            main.miner_numbers += 1
                            main.member_nodes.pop(0)
                            main.transactions.append(new_transaction)

            main.nodes_approved = []

        if(len(main.miners_approved) > 0):
            for transaction in main.miners_approved:
                miner = Miner(topology=main,is_miner=True)
                miner.public_key = transaction.origin_public_key
                for node in main.everything:
                    if (miner.public_key == node.public_key):
                        print("achou a chave")
                        miner.private_key = node.private_key
                main.miner_numbers += 1        
                main.teste.append(miner)
                #for node in main.everything:
                    #if(miner != node):
                        #node.check_bloom_filter(miner.public_key)

            main.miners_approved = []

        for node in main.nodes():
            if (node.is_miner):
                node.do_miner_step(step)

        if(step in main.new_nodes_flow):
            pass

        if(step in main.made_key):
            (public_key,private_key) = main.make_keys()
            main.keys_tuple.append((public_key.n,private_key))
            new_transaction = Transaction(2,step-110)
            new_transaction.identify = main.identify
            new_transaction.origin_public_key = public_key.n
            content = "{}{}{}{}".format(new_transaction.identify,new_transaction.born_step,
                new_transaction.transaction_type,public_key.n)
            new_transaction.origin_signature = rsa.sign(content.encode('utf-8'), private_key, 'SHA-1')
            main.identify += 1
            main.transactions.append(new_transaction)

            data = {}
            data[new_transaction.identify] = []
            data[new_transaction.identify].append({
                "born_step" : new_transaction.born_step,
                "keys_creation_step" : (new_transaction.born_step+110),
                "origin_public_key" : new_transaction.origin_public_key,
                "origin_signature" : str(new_transaction.origin_signature)
                })
            main.emiss_trans.append(data)

    with open("trans_emiss.json","w") as outfile:
        json.dump(main.emiss_trans,outfile)

    with open("block_mined.json","w") as outfile:
        json.dump(main.block_mined_json,outfile)
