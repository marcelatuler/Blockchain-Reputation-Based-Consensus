import datetime as date

class Tables:
    identificationTable = []
    trustTable = []
    ejectedTable = []


class Table:
    index = 0
    public_key = None
    timestamp = None

    def set_timestamp(self):
        self.timestamp = date.datetime.now()

    def read_table(self):
        pass

    def write_table(self):
        pass


@DeprecationWarning
class IdentificationTable(Table):

    miner = 0

    def add_node_to_table(self):
        pass

    def update_miner_status(self):
        pass


class TrustTable(Table):

    grade = 0.0

    def update_grade(self):
        pass

    def update_timestamp(self):
        pass

    def __str__(self):
        return "Public Key: {} | Grade: {} | Timestamp: {}".format(self.public_key, self.grade, self.timestamp)

class EjectedTable(Table):

    issuing_judge = None  # Hash
    issuing_date = None  # Timestamp

    def transactions_account(self):
        pass

    def transactions_computer(self):
        # orders transactions
        pass