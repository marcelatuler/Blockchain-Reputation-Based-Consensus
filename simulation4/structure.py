import hashlib, time
import datetime as date
from threading import Thread

GENESIS_DATA = "Genesis Block"
GENESIS_HASH = 0x00
WAITING = 0
VALIDATED = 1
INVALID = 2


class Block:
    transaction = None
    trust_type = 0
    issuing_sign = None
