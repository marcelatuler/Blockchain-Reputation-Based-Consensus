from const import *
import datetime as date
import rsa
import io
#import panda as pd

class Transaction:
    transaction_type = 0
    origin_public_key = None  
    origin_signature = None  

    born_step = 0  # Set on object creation {Valid time out}
    identify = 0

    validation_public_key = None
    validation_signature = None
    validation_step = 0

    def __init__(self, transaction_type,step):
        self.transaction_type = transaction_type
        self.born_step = step

    def sign_transactions(self, transaction):
        pass

    def sign_transaction(self,node,identify):
        self.identify = identify
        content = "{}{}{}{}".format(self.identify,self.born_step,self.transaction_type, node.public_key.n)
        self.origin_public_key = node.public_key
        self.origin_signature = rsa.sign(content.encode('utf-8'), node.get_private_key(), 'SHA-1')

    def sign_miner_trust(self, node, step):
        self.validation_step = step
        self.validation_public_key = node.public_key.n
        content = "{}{}{}{}{}{}{}".format(self.identify,self.born_step,self.transaction_type, self.origin_public_key, self.origin_signature, node.public_key,self.validation_step)
        self.validation_signature = rsa.sign(content.encode("utf-8"), node.get_private_key(), 'SHA-1')


class Ingress(Transaction):
    # Ingress at the network
    reliable_node_signature = None  # Hash signature of the trusted node
    reliable_node_public_key = None

    def __init__(self):
        Transaction.__init__(self, TRANSACTIONS.get("ingress"))

    def sign_transactions(self, node):
        content = "{}{}".format(self.transaction_type, node.public_key.n)
        self.issuing_public_key = node.public_key
        print(self.issuing_public_key)
        self.issuing_signature = rsa.sign(content.encode('utf-8'), node.get_private_key(), 'SHA-1')

    def sign_trust(self, node):
        print(node.get_private_key())
        content = "{}{}{}{}{}{}{}".format(self.transaction_type, self.issuing_public_key, self.issuing_signature, node.public_key),
        self.reliable_node_signature = rsa.sign(content.encode("utf-8"), node.get_private_key(), 'SHA-1')
        self.timestamp = date.datetime.now()
        self.save()

    def save(self):
        print("Saving transaction")
        with open("blockchain/validated_transactions.csv", "a") as blockchain_file:
            line = "{};{};{};{};{};{}\n".format(self.transaction_type, self.issuing_public_key,
                                       self.issuing_signature, self.reliable_node_public_key,
                                       self.reliable_node_signature, self.timestamp)
            blockchain_file.write(line)


class TransactionMiner(Transaction):
    # Upgrade Node to Miner
    ingress_timestamp = None  # Date
    reliable_node_signature = None  # Hash signature of the trusted node


class ExpulsionRequest(Transaction):
    judged_node_public_key = None


class Expulsion(Transaction):
    judged_node_public_key = None
    expulsion_timestamp = None
    signatures = None  # (J/2 +1): Hash