import networkx as nx
from nodes import *
import time

# Class Graph with methods to generate Miners and Nodes

class Graph(nx.Graph):

    def __init__(self):
        nx.Graph.__init__(self)

    def make_nodes(self, amount, topology=None):
        nodes = []
        raw_nodes = []
        amount = (amount - int((amount/miners_rate)))
        for i in range(amount):
            new_node = Node(topology=topology)
            new_node.make_keys()
            new_node.set_timestamp()

            nodes.append((i, new_node.get_dict()))
            raw_nodes.append(new_node)

        self.add_nodes_from(nodes)
        return raw_nodes

    def make_miners(self, nodes, amount, topology):
        raw_nodes = []
        for i in range(amount):
            new_miner = Miner(topology=topology)
            new_miner.set_private_key(nodes[i].get_private_key())
            new_miner.public_key = nodes[i].public_key
            raw_nodes.append(new_miner)


        return raw_nodes