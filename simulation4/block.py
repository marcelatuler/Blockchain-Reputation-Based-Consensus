import random

class Block:
	
	def __init__(self,key=""):
		self.is_malicious = False
		self.owner_public_key = key
		self.transactions = []

	def set_transactions(self,transaction):
		pass