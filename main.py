# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "rsa",
# ]
# ///

import hashlib
import time
import rsa

class Transaction:
    def __init__(self, sender, recipient, amount, fee=0):
        self.sender = sender
        self.recipient = recipient
        self.amount = amount
        self.fee = fee
        self.timestamp = int(time.time())
        self.signature = None

    def sign(self, sender_private_key):
        message = str(self.sender) + str(self.recipient) + str(self.amount) + str(self.fee) + str(self.timestamp)
        self.signature = rsa.sign(message.encode(), sender_private_key, 'SHA-256')

    def is_valid(self):
        if self.signature is None and self.sender is not None:  # Allow null sender for mining rewards
            return False
        if self.amount <= 0 or self.fee < 0:
            return False
        if self.sender == self.recipient:
            return False
        message = str(self.sender) + str(self.recipient) + str(self.amount) + str(self.fee) + str(self.timestamp)
        try:
            rsa.verify(message.encode(), self.signature, self.sender)
            return True
        except rsa.VerificationError:
            return False

class Wallet:
    def __init__(self):
        self.private_key, self.public_key = rsa.newkeys(512)

    def create_transaction(self, recipient, amount, fee=0):
        transaction = Transaction(self.public_key, recipient, amount, fee)
        transaction.sign(self.private_key)
        return transaction

    def calculate_balance(self, blockchain):
        balance = 0
        for block in blockchain.blocks:
            for transaction in block.transactions:
                if transaction.sender == self.public_key:
                    balance -= (transaction.amount + transaction.fee)
                if transaction.recipient == self.public_key:
                    balance += transaction.amount
        return balance

class TransactionPool:
    def __init__(self):
        self.pending_transactions = []

    def add_transaction(self, transaction):
        if transaction.is_valid():
            self.pending_transactions.append(transaction)
            return True
        return False

    def get_transactions(self, max_size=10):
        # Sort by fee (highest first)
        sorted_transactions = sorted(
            self.pending_transactions,
            key=lambda t: t.fee,
            reverse=True
        )
        return sorted_transactions[:max_size]

    def remove_transactions(self, transactions):
        for tx in transactions:
            if tx in self.pending_transactions:
                self.pending_transactions.remove(tx)

class Block:
    def __init__(self, index, previous_hash, timestamp, transactions, hash, nonce):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.transactions = transactions
        self.hash = hash
        self.nonce = nonce

class Blockchain:
    def __init__(self):
        self.blocks = []
        self.difficulty = 4
        self.target_block_time = 10  # The time we want blocks to take (in seconds)
        self.adjustment_interval = 10  # How many blocks to consider for adjustment
        self.block_reward = 50
        self.mempool = TransactionPool()
        self.min_fee = 0.001

    def calculate_hash(self, index, previous_hash, timestamp, transactions, nonce):
        transaction_data = "".join(str(tx.__dict__) for tx in transactions)
        value = str(index) + str(previous_hash) + str(timestamp) + transaction_data + str(nonce)
        return hashlib.sha256(value.encode('utf-8')).hexdigest()

    def proof_of_work(self, index, previous_hash, timestamp, transactions):
        target = '0' * self.difficulty
        for nonce in range(2 ** 32):
            hash_result = self.calculate_hash(index, previous_hash, timestamp, transactions, nonce)
            if hash_result[:self.difficulty] == target:
                return nonce, hash_result
        return None, ''

    def adjust_difficulty(self):
        if len(self.blocks) < self.adjustment_interval:
            return
        newest_block = self.blocks[-1]
        oldest_block = self.blocks[-self.adjustment_interval]
        time_diff = newest_block.timestamp - oldest_block.timestamp
        average_block_time = time_diff / self.adjustment_interval
        if average_block_time < self.target_block_time:
            self.difficulty += 1
        else:
            self.difficulty -= 1

    def is_valid_block(self, block, previous_block):
        if block.previous_hash != previous_block.hash:
            return False
        if block.index != previous_block.index + 1:
            return False
        if block.timestamp <= previous_block.timestamp:
            return False
        
        # Verify block hash
        calculated_hash = self.calculate_hash(
            block.index,
            block.previous_hash,
            block.timestamp,
            block.transactions,
            block.nonce
        )
        if calculated_hash != block.hash:
            return False

        # Verify all transactions
        total_fees = 0
        for tx in block.transactions:
            if not tx.is_valid():
                return False
            total_fees += tx.fee

        # Verify mining reward
        reward_tx = [tx for tx in block.transactions if tx.sender is None]
        if len(reward_tx) != 1:
            return False
        if reward_tx[0].amount != self.block_reward + total_fees:
            return False

        return True

    def create_genesis_block(self, miner_wallet):
        transactions = []
        nonce, hash_result = self.proof_of_work(0, "0", int(time.time()), transactions)
        block = Block(0, "0", int(time.time()), transactions, hash_result, nonce)
        
        # Add genesis reward
        reward_transaction = Transaction(None, miner_wallet.public_key, self.block_reward)
        block.transactions.append(reward_transaction)
        
        return block

    def create_new_block(self, previous_block, transactions):
        index = previous_block.index + 1
        timestamp = int(time.time())
        nonce, hash_result = self.proof_of_work(index, previous_block.hash, timestamp, transactions)
        return Block(index, previous_block.hash, timestamp, transactions, hash_result, nonce)

    def add_block(self, block, miner_wallet):
        if miner_wallet is None:
            raise ValueError("Miner's wallet cannot be null")

        if len(self.blocks) > 0:
            if not self.is_valid_block(block, self.blocks[-1]):
                raise ValueError("Invalid block")

            # Calculate total transaction fees (skip for genesis block)
            total_fees = sum(tx.fee for tx in block.transactions if tx.sender is not None)
            
            # Create mining reward transaction including fees
            reward_transaction = Transaction(
                None,
                miner_wallet.public_key,
                self.block_reward + total_fees
            )
            block.transactions.append(reward_transaction)

        self.blocks.append(block)
        self.mempool.remove_transactions(block.transactions)
        self.adjust_difficulty()

def main():
    # Initialize blockchain and create genesis miner wallet
    blockchain = Blockchain()
    miner_wallet = Wallet()
    
    # Create genesis block with miner wallet
    genesis_block = blockchain.create_genesis_block(miner_wallet)
    blockchain.add_block(genesis_block, miner_wallet)

    # Create user wallets
    alice_wallet = Wallet()
    bob_wallet = Wallet()

    # Create some transactions
    tx1 = alice_wallet.create_transaction(bob_wallet.public_key, 10, fee=0.1)
    tx2 = bob_wallet.create_transaction(alice_wallet.public_key, 5, fee=0.2)

    # Add transactions to mempool
    blockchain.mempool.add_transaction(tx1)
    blockchain.mempool.add_transaction(tx2)

    # Mine some blocks
    for i in range(5):
        transactions = blockchain.mempool.get_transactions()
        new_block = blockchain.create_new_block(blockchain.blocks[-1], transactions)
        blockchain.add_block(new_block, miner_wallet)
        print(f"Block #{new_block.index} mined! Hash: {new_block.hash[:10]}...")

    # Print final balances
    print(f"Miner balance: {miner_wallet.calculate_balance(blockchain)}")
    print(f"Alice balance: {alice_wallet.calculate_balance(blockchain)}")
    print(f"Bob balance: {bob_wallet.calculate_balance(blockchain)}")

if __name__ == "__main__":
    main()

