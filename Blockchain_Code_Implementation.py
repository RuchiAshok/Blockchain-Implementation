# -*- coding: utf-8 -*-
"""
Created on Wed Sep 21 03:08:45 2022

@author: pujag
"""


# Importing the libraries
import datetime
import hashlib
import json
from flask import Flask, jsonify, request
import requests
from uuid import uuid4
from urllib.parse import urlparse
from Crypto.PublicKey import RSA
import binascii     
import Crypto
import Crypto.Random
import os
from os import path
from Crypto.Hash import SHA
import random
from Crypto.Signature import PKCS1_v1_5


#Create a class to store User Credentials : Public Key, Private Key, Wallet Address, Username, Wallet Amount
class User_Credentials:
    def __init__(self, private_key: RSA.RsaKey, public_key: bytes, bitcoin_address: bytes,user_name:str):
        self.private_key = private_key
        self.public_key = public_key
        self.bitcoin_address = bitcoin_address
        self.user_name = user_name
        #Initially all users are given 100 coins for transactions
        self.wallet_amount = 100
        
#Initialize Mew private key, public key and address for new users
def initialize_Wallet_Credentials(user_name:str=""):
    random_gen = Crypto.Random.new().read
    private_key = RSA.generate(1024, random_gen)
    public_key = private_key.publickey()
    bitcoin_address = PKCS1_v1_5.new(private_key)
    wallet =  User_Credentials(private_key, public_key, bitcoin_address,user_name)
    return wallet


#Building a Blockchain
class Blockchain:

    def __init__(self):
        
        # Will have all the blocks of the blockchain
        self.chain = []
        
        # After a block is mined maked this transactions list empty
        self.transactions = []
        
        # To check if our Blockchain is empty or not
        ifChainEmpty = self.getLatestBlockChain()
        
        # If blockchain is empty create Genesis Block
        if(ifChainEmpty == False):
            #Create Genesis block
            self.create_block(proof = 1, previous_hash = '0')
        
        #Used for Decentralization - Connection of all the nodes for P2P transfer
        self.nodes = set()
        
        #To get credentials of all logged users
        self.user = []

        
    # To get the latest blockchain stored in out db
    def getLatestBlockChain(self):
        filename = '/Users/pujag/OneDrive/Desktop/Semester 3/Blockchain/Blockchain.json'
        list_blockChain = []
         
        # Check if file exists
        if path.isfile(filename) is False:
          print("BlockChain is empty")
          return False
        else:
            # Read JSON file and update the chain
            with open(filename) as fp:
              list_blockChain = json.load(fp)
            if(len(list_blockChain)>0):
                self.chain = list_blockChain     
                return True
        return False
    
    # For creating a new Block : Mining a block
    def create_block(self, proof, previous_hash):
        merkle_root_hash = self.merkle_root()
        #Divide the Block into two part - Header and Body
        block_header = {'index': len(self.chain) + 1,
                 'timestamp': str(datetime.datetime.now()),
                 'proof': proof,
                 'previous_hash': previous_hash,
                 'merkle_root': merkle_root_hash}
        block_body = {'transactions': self.transactions}
        block = {'header':block_header,
                 'body':block_body}
        
        #Delete transactions from transactions_memory.json "transactions memory pool" once block is created
        if(previous_hash!='0'):
            file_path = '/Users/pujag/OneDrive/Desktop/Semester 3/Blockchain/transactions_memory.json'
            if os.path.isfile(file_path):
              os.remove(file_path)
              print("File has been deleted")
            else:
              print("File does not exist")
        self.transactions = []
        
        self.chain.append(block)
        
        #Add the block in the Blockchain.json file
        self.store_BlockChain(block)
        return block
    
    #To store the blocks of the Blockchain in db
    def store_BlockChain(self,block):
        filename = '/Users/pujag/OneDrive/Desktop/Semester 3/Blockchain/Blockchain.json'
        list_blockChain = []
         
        # Check if file exists
        if path.isfile(filename) is False:
          print("Blockchain File created")
          filename = 'Blockchain.json'   
          list_blockChain.append(block)
          with open(filename, 'w') as file_object:  
              json.dump(list_blockChain, file_object)
        else:
            # Read JSON file
            with open(filename) as fp:
              list_blockChain = json.load(fp)
             
            list_blockChain.append(block)
             
            with open(filename, 'w') as json_file:
                json.dump(list_blockChain, json_file)
             
            print('Blocks Successfully appended to the Blockchain.file')
    
    
    # To get the last block of the Blockchain
    def get_previous_block(self):
        self.getLatestBlockChain()
        return self.chain[-1]

    """
    Our Consensus Algorithm : Proof of Work for mining a block
    Used for mining a block : i.e. adding a new block in blockchain
    Perform some mathematical computation and return proof by checking leading "0000"
    
    """
    def proof_of_work(self, previous_proof):
        new_proof = 1
        check_proof = False
        while check_proof is False:
            hash_operation = hashlib.sha256(str(new_proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[:4] == '0000':
                check_proof = True
            else:
                new_proof += 1
        return new_proof
    
    
    #Function for randomly slecting leader between 1 to 10 miner nodes
    def miner_leaderSelection(self):
        miner_node = random.randint(1,10)
        print("Selected Miner ",miner_node)
        network = self.nodes
        isMinerFound  = False
        for node in network:
            if(str(node[-1])==str(miner_node)):
                #After leader selection - Mining the Block
                """
                1. Broadcast all the transactions in the memory pool to all the nodes
                2. Validate digital signature of all the transactions while mining
                3. Mine the Block - based on leader selected node randomly between 1 to 10, mining will be donr
                """
                isMinerFound  = True
                
                # Broadcasting the transactions to all miners P2P
                self.broadcast_transactions()
                #Mining the block based on leader selection
                response = requests.get(f'http://{node}/mine_block')
                if response.status_code == 200:
                    print("New Block added to the blockchain")
                    return True
        
        #Added to cover the logic that leader miner is the same as the one to which users are connected
        if(isMinerFound == False ):
            self.broadcast_transactions()
            node ='127.0.0.1:5001'    #Change the node number (5001) depends upon which miner is running
            response = requests.get(f'http://{node}/mine_block')
            if response.status_code == 200:
                print("New Block added to the blockchain")
                return True
        
        return False
    

    # To get hash of a block/transactions
    def hash(self, block):
        encoded_block = json.dumps(block, sort_keys = True).encode()
        return hashlib.sha256(encoded_block).hexdigest()
    
    
    """
    Our logic includes that if number of transactions in the memory pool >=4, block will be mined
    Based on above logic, merkle root function is written to handel hash of 4 transactions
    
    """
    def merkle_root(self):
        #Taken the constarints that Block can contain a maximum of 4 transactions per block
        mr=0
        l=len(self.transactions)
        if(len(self.chain)==0):
            return 0
        if(l==1):
            md1 = self.transactions[0]['input']['transaction_hash']
            mr = self.hash(md1)
        elif(l==2):
            md1 = self.transactions[0]['input']['transaction_hash']
            md2 = self.transactions[1]['input']['transaction_hash']
            temp = {'data1':md1,
             'data2':md2}
            mr = self.hash(temp)
        elif(l==3):
            md1 = self.transactions[0]['input']['transaction_hash']
            md2 = self.transactions[1]['input']['transaction_hash']
            temp = {'data1':md1,
             'data2':md2}
            mr = self.hash(temp)
            md3 = self.transactions[2]['input']['transaction_hash']
            temp = {'md1':md1,
             'md2':md3}
            mr = self.hash(temp)
        elif(l==4):
            md1 = self.transactions[0]['input']['transaction_hash']
            md2 = self.transactions[1]['input']['transaction_hash']
            temp = {'data1':md1,
             'data2':md2}
            md_1 = self.hash(temp)
            md3 = self.transactions[2]['input']['transaction_hash']
            md4 = self.transactions[3]['input']['transaction_hash']
            temp = {'data3':md3,
             'data4':md4}
            md_2= self.hash(temp)
            temp = {'md1':md_1,
             'md2':md_2}
            mr = self.hash(temp)
        else:
            mr = self.hash(l)
        return mr
    
    # Used for decentralization and check the validity of the blockchain
    def is_chain_valid(self, chain):
        previous_block = chain[0]
        block_index = 1
        while block_index < len(chain):
            block = chain[block_index]
            #Cheching for all block previous hash is correct or not
            if block['header']['previous_hash'] != self.hash(previous_block):
                return False
            previous_proof = previous_block['header']['proof']
            proof = block['header']['proof']
            
            #Checking for all blocks if proof has been correct or not.
            hash_operation = hashlib.sha256(str(proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[:4] != '0000':
                return False
            previous_block = block
            block_index += 1
        return True
    
    
    #For digitally signing the transactions
    def transaction_digital_signing(self,transaction_hash,sender_credentials):
        h = SHA.new(transaction_hash.encode('utf8'))
        return binascii.hexlify(sender_credentials.bitcoin_address.sign(h)).decode('ascii')
    
    #For storing the transactions in the memory pool (db) after a transaction is added
    def store_transactions_mempool(self,transactions):
        filename = '/Users/pujag/OneDrive/Desktop/Semester 3/Blockchain/transactions_memory.json'
        list_transactions = []
         
        # Check if file exists
        if path.isfile(filename) is False:
          print("Transactions File created")
          filename = 'transactions_memory.json'   
          list_transactions.append(transactions)
          with open(filename, 'w') as file_object:  
              json.dump(list_transactions, file_object)
        else:
            # Read JSON file
            with open(filename) as fp:
              list_transactions = json.load(fp)
             
            #print(list_transactions)
            list_transactions.append(transactions)
            #print(list_transactions)
             
            with open(filename, 'w') as json_file:
                json.dump(list_transactions, json_file)
             
            print('Transactions Successfully appended to the JSON file')
    
    
    # Adding a new Transaction in the transaction list5
    def add_transaction(self, sender, receiver, amount,sender_credentials: User_Credentials,
                        receiver_bitcoin_address: bytes,receiver_public_key,transaction_type:str=""):
        
        transac = {'sender': sender,
                   'receiver': receiver,
                   'amount': amount}
        transac_hash = self.hash(transac)
        
        # Digitally sign transactions
        signature = self.transaction_digital_signing(transac_hash,sender_credentials)
        
        # Storing Transactions in UTXO format
        tran_utxo ={}
        sender_public_key_hash = self.hash(str(sender_credentials.public_key))
        receiver_public_key_hash = self.hash(str(receiver_public_key))
        
        #tran_utxo['sender_wallet_address']=sender_credentials.bitcoin_address.decode("utf-8"),
        tran_utxo['input']={"transaction_hash": transac_hash,  #transaction hash,
                            "sender":sender,
                            "sender_public_key": sender_public_key_hash, #sender's public key
                            "signature": signature}                #sender signature
        tran_utxo['output']={"amount": amount,  #amount
                             "receiver":receiver,
                            "receiver_public_key": receiver_public_key_hash,    #user2 public key hash
                            #"receiver_wallet_address":receiver_bitcoin_address.decode("utf-8"),
                            }
        
        # To store the transactions in the UTXO format if specified
        if(transaction_type == "UTXO"):
            self.transactions.append(tran_utxo)
            self.store_transactions_mempool(tran_utxo)
            
            #Broadcast Transactions from memory pool to all the nodes
            self.broadcast_transactions()
            
            #If length of transactions is greater than four, then mine block based on consensus and leader selection
            if(len(self.transactions)>=4):
                # Mine Block
                print("Transactions > 4")
                ismined = self.miner_leaderSelection()
                if(ismined):
                    print ("Blockchain mined successfully")
            
        else:
            # To store the transactions in the normal format
            self.transactions.append({
            #'sender_address': sender_credentials.bitcoin_address.decode("utf-8"),
            #'receiver_address': receiver_bitcoin_address.decode("utf-8"),
            'sender':sender,
            'receiver':receiver,
            'amount': amount,
            'signature': signature,
            'transaction_hash':transac_hash
            })
 
        previous_block = self.get_previous_block()
        return previous_block['header']['index'] + 1
    
    # For adding a node for P2P connection
    def add_node(self, address):
        parsed_url = urlparse(address)
        self.nodes.add(parsed_url.netloc)
    
    # For broadcasting transactions from memory pool to all the miners
    def broadcast_transactions(self):
        filename = '/Users/pujag/OneDrive/Desktop/Semester 3/Blockchain/transactions_memory.json'
        list_transactions = []
         
        # Check if file exists
        if path.isfile(filename) is False:
          print("Transaction MemPool is empty")
          return False
        else:
            # Read JSON file
            with open(filename) as fp:
              list_transactions = json.load(fp)
             
            self.transactions = list_transactions     
            print('Transactions updated')
            return True
     
    
    # For new user Wallet Initialization
    def user_wallet_initialization(self,user_name):
        user_key = initialize_Wallet_Credentials(user_name)
        #print(len(self.user))
        self.user.append(user_key)
        return user_key
    
    # For verifying transaction signature while mining the block
    def verify_signature(wallet_address, message, signature):
        pubkey = RSA.importKey(binascii.unhexlify(wallet_address))
        verifier = PKCS1_v1_5.new(pubkey)
        h = SHA.new(message.encode('utf8'))
        return verifier.verify(h, binascii.unhexlify(signature))
    
    
    # To validate the transactions while mining whether the transaction is valid or not
    def validate_transactions(self):
        valid_key  =True
        if(len(self.transactions)==0):
             return valid_key
        
        sender_credentials = None
        #receiver_credentials = None
        
        for i in range(len(self.transactions)):
            for j in range(len(self.user)):
                if(self.user[j].user_name == self.transactions[i]['input']['sender']):
                    sender_credentials = self.user[j]
                """
                if(self.user[j].user_name == self.transactions[i]['output']['receiver']):
                    receiver_credentials = self.user[j]
                """
            #verify digital signature
            try:
                transaction_hash = self.transactions[i]['input']['transaction_hash']
                signature = self.transactions[i]['input']["signature"]
                address =  binascii.hexlify(sender_credentials.public_key.exportKey(format='DER')).decode('ascii')
                assert self.verify_signature(address, transaction_hash, signature)
            except:
                #print("Digital Signature Not Verified")
                return valid_key
        return valid_key



# Creating a Web Application
app = Flask(__name__)

# Creating an address for the node on Port 5001
node_address = str(uuid4()).replace('-', '')

# Creating an instance for the Blockchain
blockchain = Blockchain()

# Mining a new block 
@app.route('/mine_block', methods = ['GET'])
def mine_block():
    previous_block = blockchain.get_previous_block()
    previous_proof = previous_block['header']['proof']
    proof = blockchain.proof_of_work(previous_proof)
    previous_hash = blockchain.hash(previous_block)
    
    #Broadcast all the transactions in the mempool to all the miners
    blockchain.broadcast_transactions()
    
    #Validate Signature
    is_valid = blockchain.validate_transactions()
    if(not is_valid ):
        response = {'message': 'Error Occurred: Transactions are not digitally verified'}
        return jsonify(response), 200
    else:
        # Create a new block
        block = blockchain.create_block(proof, previous_hash)
        
        # Each block should have two part, header and body
        block_header = {'index': block['header']['index'],
                        'timestamp': block['header']['timestamp'],
                        'proof': block['header']['proof'],
                        'previous_hash': block['header']['previous_hash'],
                        'merkle_root': block['header']['merkle_root']}
        block_body = {'transactions': block['body']['transactions']}
        response = {'message': 'Congratulations, you just mined a block!',
                    'header':block_header,
                    'body':block_body}
        return jsonify(response), 200



# Getting the full Blockchain
@app.route('/get_chain', methods = ['GET'])
def get_chain():
    blockchain.getLatestBlockChain()
    response = {'chain': blockchain.chain,
                'length': len(blockchain.chain)}
    return jsonify(response), 200

#Broadcasting Transactions to all the miner : For testing purpose, if woring or not
@app.route('/broadcast_transactions', methods = ['GET'])
def broadcast_transactions():
    is_transaction_replaced = blockchain.broadcast_transactions()
    if is_transaction_replaced:
        response = {'message': 'The transactions has been broadcasted to all the miners',
                    'transactions': blockchain.transactions}
    else:
        response = {'message': 'No new transactions found from the memory pool',
                    'actual_chain': blockchain.transactions}
    return jsonify(response), 200


# Checking if the Blockchain is valid
@app.route('/is_valid', methods = ['GET'])
def is_valid():
    is_valid = blockchain.is_chain_valid(blockchain.chain)
    if is_valid:
        response = {'message': 'All good. The Blockchain is valid.'}
    else:
        response = {'message': 'There has been a malpractice, some data has been altered. The Blockchain is not valid.'}
    return jsonify(response), 200

# Adding a new transaction to the Blockchain
@app.route('/add_transaction', methods = ['POST'])
def add_transaction():
    json = request.get_json()
    transaction_keys = ['sender', 'receiver', 'amount']
    if not all(key in json for key in transaction_keys):
        return 'Some elements of the transaction are missing', 400
    
    logged_users = blockchain.user
    sender_credentials = None
    receiver_credentials = None
    
    #Sender's Wallet Address
    for i in range(len(logged_users)):
        if(logged_users[i].user_name == json['sender']):
            sender_credentials = logged_users[i]
            

        
    #Receiver's Wallet Address
    for i in range(len(logged_users)):
        if(logged_users[i].user_name == json['receiver']):
            receiver_credentials = logged_users[i]
            
    # Transaction type has been specified as "UTXO" - if not mentioned will have normal header and body
    index = blockchain.add_transaction(json['sender'], json['receiver'], json['amount'],
                                       sender_credentials,receiver_credentials.bitcoin_address,
                                       receiver_credentials.public_key,
                                       transaction_type="UTXO")
    response = {'message': f'This transaction will be added to Block {index}'}
    return jsonify(response), 201

        
#Decentralizing our Blockchain

# Connecting new nodes
@app.route('/connect_node', methods = ['POST'])
def connect_node():
    json = request.get_json()
    nodes = json.get('nodes')
    if nodes is None:
        return "No node", 400
    for node in nodes:
        blockchain.add_node(node)
    print(blockchain.nodes)
    response = {'message': 'All the nodes are now connected. The Blockchain now contains the following nodes:',
                'total_nodes': list(blockchain.nodes)}
    return jsonify(response), 201



# Part 5 - Connecting to users to the miners
@app.route('/user_connect', methods = ['POST'])
def user_connect():
    json = request.get_json()
    user_keys = ['user_name']
    if not all(key in json for key in user_keys):
        return 'Some elements of the user login are missing', 400
    user = blockchain.user_wallet_initialization(json['user_name'])
    
    print("User's user name: ", user.user_name)
    print("User Public Key:", user.public_key)
    print("User Private Key:", user.private_key)
    print("User's wallet address:", user.bitcoin_address)
    print("User's Wallet amount: ",user.wallet_amount)
    #print("*******************************************************************")
    
    response ={'user_name':user.user_name,
               'user_public_key':str(user.public_key),
               'message':"User Successfully connected to the blockchain network"
               }
    return jsonify(response), 200

# Running the app
app.run(host = '0.0.0.0', port = 5001)
