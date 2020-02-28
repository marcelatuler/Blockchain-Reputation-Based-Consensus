import random

class Block:
	
	def __init__(self,owner_public_key):
		self.is_malicious = False
		self.owner_public_key =  owner_public_key
		self.transactions = []

	def set_transactions(self,transaction):
		pass