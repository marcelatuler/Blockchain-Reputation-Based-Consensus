import networkx as nx
from nodes import *
import time


class Graph(nx.Graph):

    def __init__(self):
        nx.Graph.__init__(self)

    def make_nodes(self, amount, topology=None):
        nodes = []
        raw_nodes = []
        for i in range(amount):
            # Create Node
            new_node = Node(topology=topology)
            new_node.make_keys()
            new_node.set_timestamp()

            nodes.append(new_node)
            raw_nodes.append(new_node)
            time.sleep(0.003)

        # Add to the network
        self.add_nodes_from(nodes)
        return raw_nodes

    def make_miners(self, nodes, amount, topology):
        raw_nodes = []
        for i in range(amount):
            # Create Node
            # print(nodes)
            new_miner = Miner(topology=topology,is_miner=True)
            new_miner.set_private_key(nodes[i].get_private_key())
            new_miner.public_key = nodes[i].public_key
            nodes.remove(nodes[i])
            self.remove_node(nodes[i])
            raw_nodes.append(new_miner)

            # self.node[i]["timestamp"] = newMiner.timestamp
            time.sleep(0.003)

        # Add to the network
        self.add_nodes_from(raw_nodes)
        return raw_nodes