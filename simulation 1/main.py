# imports

from nodes import *
from transactions import *
from threading import Thread
from topology.graph import Graph
from scipy.stats import dgamma
import os
import json
import sys


class Topology(Graph):

    def __init__(self, initial_nodes=number_of_nodes):
        Graph.__init__(self)
		
		# creates nodes and miners based on miners_rate        
        self.member_nodes = self.make_nodes(initial_nodes, self)
        self.miners = self.make_miners(self.member_nodes, round(initial_nodes/miners_rate), self)


        # array with everything ( nodes and miners )
        self.everything = []

        for miner in self.miners:
            self.everything.append(miner)

        for node in self.member_nodes:
            self.everything.append(node)

        # array for transactions and validated transactions
        self.transactions = []
        self.validated_transactions = []

        # id's for the output json
        self.id = 0
        self.block_id = 0

       	#
        self.block_closed_flow = []

        # which miner will close the block
        self.vez = 0

        self.all_nodes = self.number_of_nodes()

        # array for json results
        self.emiss_json = []
        self.validate_json = []
        self.block_mined_json = []

        self.emiss_array = []


    def insert_node(self, node):
        node.topology = self
        self.insertion_queue.append(node)

    # generating block flow with dgamma.rvs 
    def make_block_flow(self,max_steps):
        step = 0
        # default parameters from multichain 
        while step <= max_steps:
            time_block = dgamma.rvs(2.0000170661444634, 5.4611854838492295, 0.8244588748930897)
            time_block = int(round(time_block)) * 1000
            step += time_block
            self.block_closed_flow.append(step)


if __name__ == "__main__":

	# creates the topology for a given number of nodes
    main = Topology(initial_nodes=number_of_nodes)

    # simulation in ms, our standard its 1 hour, 3600000 ms
    simulation_steps = 3600000

    # generates a block flow
    main.make_block_flow(simulation_steps)

    for nodes in main.everything:
        nodes.make_emiss_flow(simulation_steps)


    # runs the simulation
    for step in range(simulation_steps):

    	# each node does his job for the given step
        for node in main.everything:
            node.do_step(step)

        # each miner does his job for the given step
        for miner in main.miners:
            if(step in main.block_closed_flow):
                miner.do_miner_step(step)
                if(main.vez == len(main.miners)-1):
                    main.vez = 0
                else:
                    main.vez = 1

    with open("trans.json","w") as outfile:
        json.dump(main.emiss_json,outfile)

    with open("validated_transactions.json","w") as outfile:
        json.dump(main.validate_json,outfile)

    with open("block_mined.json","w") as outfile:
        json.dump(main.block_mined_json,outfile)