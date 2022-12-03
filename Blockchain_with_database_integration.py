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
#import binascii     
import Crypto
import Crypto.Random
from hashlib import sha512
#from Crypto.Hash import SHA
import random
from Crypto.Signature import PKCS1_v1_5
import mysql.connector

mydb = mysql.connector.connect(host="localhost",user="root",passwd="Puja@123",database="blockchain")
mycursor = mydb.cursor()

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


# Common function for retriving block information from database
def response_block_data_db(myresult):
    block_header={}
    block_body={}
    blockData =[]
    
    if(len(myresult)>0):      
        for x in myresult:
            block_header={
                'index':int(x[0]),
                'merkle_root':x[1],
                'previous_hash':x[2],
                'proof':int(x[3]),
                'block_hash':x[4],
                'timestamp':str(x[5])}
        
            block_body={}
            sql = "SELECT * FROM Transactions where blockIndex = %s"   
            adr =(int(x[0]),)
            mycursor.execute(sql, adr)
            mytrans = mycursor.fetchall()
            trans_data =[]
            
            if(len(mytrans)>0):      
                for i in mytrans:
                    
                    transation_data ={
                        'input':{"transaction_hash": i[5],  
                                 "sender":i[3],
                                 "transaction_address": i[6], 
                                 "signature": i[7]},
                        'output':{"amount": i[2],  #amount
                                  "receiver":i[4]
                                  #"receiver_public_key": receiver_public_key_hash
                                  }
                        }
                    trans_data.append(transation_data)
            
            block_body = {'transactions': trans_data}
            blockData.append({
                'header':block_header,
                'body':block_body,
                
                })          
    return block_header,block_body,blockData


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
            #self.create_block(proof = 1, previous_hash = '0')
            pass
        
        #Used for Decentralization - Connection of all the nodes for P2P transfer
        self.nodes = set()
        
        #To get credentials of all logged users
        self.user = []

        
    # To get the latest blockchain stored in out db
    def getLatestBlockChain(self):
        
        blockData =[]
        sql = "SELECT * FROM Blocks;"   
        mycursor.execute(sql)
        myresult = mycursor.fetchall()
        #print("myRes",myresult)
        _,_,blockData = response_block_data_db(myresult)
        
        if(len(blockData) == 0):
           # print("BlockChain is empty")
            return False
        else:
            self.chain = blockData
            return True
       
        #print("here: ",len(self.chain))
        return False
    
        
    
    # For creating a new Block : Mining a block
    def create_block(self, proof, previous_hash):
        
        #Added new
        
        
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
        
        # Added new
        block_hash = self.hash(block)
        block_header['block_hash'] = block_hash
        
        
        #Delete transactions from transactions_memory.json "transactions memory pool" once block is created
        sql = "SELECT * FROM Trans_Mem_Pool;"
        mycursor.execute(sql)
        mytrans_mem_pool = mycursor.fetchall()
        if(len(mytrans_mem_pool)>0): 
            #Delete from Transaction Memory Pool
            sql = "TRUNCATE table Trans_Mem_Pool;"
            mycursor.execute(sql)
            print(mycursor.rowcount, "records deleted from Transaction Memory Pool.")
            mydb.commit()
        
        self.transactions = []
        self.chain.append(block)
        #Add the block in the Blockchain.json file
        self.store_BlockChain(block)
        return block
    
    #To store the blocks of the Blockchain in db
    def store_BlockChain(self,block):

        blockTransCount = len(block['body']['transactions'])
        sql = "INSERT INTO Blocks (blockIndex,blockMerkleRoot,blockPrevHash,blockProof,blockHash,blockTransCount) VALUES (%s,%s, %s, %s, %s, %s)"
        val = (block['header']['index'],block['header']['merkle_root'],block['header']['previous_hash'],
               block['header']['proof'],block['header']['block_hash'],blockTransCount)
        mycursor.execute(sql, val)
        print(mycursor.rowcount, "record inserted in the Block Table.")
        mydb.commit()
        
        
        #Insert into Transaction Table
        print(self.transactions)
        
        if(len(block['body']['transactions'])>0):   #Not Genesis Block
            #Insert all the transactions
            for i in range(len(block['body']['transactions'])):
                #print("Inserting in Transaction table for trans no: ",i,block['body']['transactions'][i])
                t_blockIndex = block['header']['index']
                t_transAmount = block['body']['transactions'][i]['output']['amount']
                t_sender =  block['body']['transactions'][i]['input']['sender'] 
                t_receiver = block['body']['transactions'][i]['output']['receiver']
                t_transHash = block['body']['transactions'][i]['input']['transaction_hash']
                t_transSignature = block['body']['transactions'][i]['input']['signature']
                trans_address = block['body']['transactions'][i]['input']['transaction_address']
                
                sql = "INSERT INTO Transactions (blockIndex,transAmount,sender,receiver,transHash,transAddress,transSignature) VALUES (%s, %s, %s, %s, %s, %s,%s)"
                val = (t_blockIndex,t_transAmount,t_sender,t_receiver,t_transHash,trans_address,t_transSignature)
                mycursor.execute(sql, val)
                print(mycursor.rowcount, "record inserted in the Transaction Table")
                
                #Update the wallet Amount Of the Sender and the Receiver
                #1. get the sender wallet amount
                senderWalletAmount = self.getSenderData(t_sender)
                #2. get the receiver wallet amount
                receiverWalletAmount = self.getSenderData(t_receiver)
                
                #get sender and receiver userId
                senderId=""               
                sql = "SELECT * FROM Users WHERE userName = %s"
                val = (t_sender,)
                mycursor.execute(sql, val)
                myresult = mycursor.fetchall()
                if(len(myresult)>0):      
                    for each in myresult:
                        senderId = each[0]
            
                
                receiverId=""
                sql = "SELECT * FROM Users WHERE userName = %s"
                val = (t_receiver,)
                mycursor.execute(sql, val)
                myresult = mycursor.fetchall()
                if(len(myresult)>0):      
                    for each in myresult:
                        receiverId = each[0]
                
                #print("Sender's data: ",t_sender,senderId,senderWalletAmount)
                #print("Receiver's data:", t_receiver,receiverId,receiverWalletAmount)
                
                
                #3. Update the sender wallet amount
                updated_senderWalletAmount = senderWalletAmount - float(t_transAmount)
                sql = "UPDATE USERS SET userWalletAmount = %s  Where userId = %s;"
                val = (updated_senderWalletAmount,int(senderId))
                mycursor.execute(sql, val)
                #print(mycursor.rowcount, "record updated in the Users Table")
                
                #4. update the receiver wallet amount
                updated_receiverWalletAmount = receiverWalletAmount + float(t_transAmount)
                sql = "UPDATE USERS SET userWalletAmount = %s  Where userId = %s;"
                val = (updated_receiverWalletAmount,int(receiverId))
                mycursor.execute(sql, val)
                #print(mycursor.rowcount, "record updated in the Users Table")
                
                mydb.commit()
        print("Block successfully mined")
        print("********************************************************** \n")
            
    
    # To get the last block of the Blockchain
    def get_previous_block(self):
        self.getLatestBlockChain()
        # return self.chain[-1]
        # Added New
        #print("len(self.chain),",len(self.chain))
        if(len(self.chain)>0):
            return self.chain[-1]
        else:
            return 0

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
    
    
    #Function for randomly slecting leader between 1 to 2 miner nodes
    def miner_leaderSelection(self):
        miner_node = random.randint(1,1)
        print("Selected Miner ",miner_node)
        network = self.nodes
        isMinerFound  = False
        for node in network:
            if(str(node[-1])==str(miner_node)):
                #After leader selection - Mining the Block
                """
                1. Broadcast all the transactions in the memory pool to all the nodes
                2. Validate digital signature of all the transactions while mining
                3. Mine the Block - based on leader selected node randomly between 1 to 2, mining will be done
                """
                isMinerFound  = True
                
                # Broadcasting the transactions to all miners P2P
                self.broadcast_transactions()
                #Mining the block based on leader selection
                response = requests.get(f'http://{node}/mine_block')
                if response.status_code == 200:
                    #print("New Block added to the blockchain")
                    return True
        
        #Added to cover the logic that leader miner is the same as the one to which users are connected
        if(isMinerFound == False ):
            self.broadcast_transactions()
            node ='127.0.0.1:5001'    #Change the node number (5001) depends upon which miner is running
            response = requests.get(f'http://{node}/mine_block')
            if response.status_code == 200:
                #print("New Block added to the blockchain")
                return True
        
        return False
    

    # To get hash of a block/transactions
    def hash(self, block):
        encoded_block = json.dumps(block, sort_keys = True).encode()
        return hashlib.sha256(encoded_block).hexdigest()
    
    
    """
    Our logic includes that if number of transactions in the memory pool >=2, block will be mined
    Based on above logic, merkle root function is written to handel hash of 2 transactions
    
    """
    def merkle_root(self):
        #Taken the constarints that Block can contain a maximum of 4 transactions per block
        mr=0
        l=len(self.transactions)
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
    
    

    
    #For storing the transactions in the memory pool (db) after a transaction is added
    def store_transactions_mempool(self,transactions): 
        tm_transAmount = transactions['output']['amount']
        tm_sender =  transactions['input']['sender'] 
        tm_receiver = transactions['output']['receiver']
        tm_transHash = transactions['input']['transaction_hash']
        tm_transSignature = transactions['input']['signature']
        transaction_address = transactions['input']['transaction_address']
        sql = "INSERT INTO Trans_Mem_Pool (tm_transAmount,tm_sender,tm_receiver,tm_transHash,tm_transAddress,tm_transSignature) VALUES (%s, %s, %s, %s, %s, %s)"
        val = (tm_transAmount,tm_sender,tm_receiver,tm_transHash,transaction_address,tm_transSignature)
        mycursor.execute(sql, val)
        print(mycursor.rowcount, "record inserted in the Transaction Memory Pool")
        mydb.commit()
        
    
    # Adding a new Transaction in the transaction list5
    def add_transaction(self, sender, receiver, amount,transaction_type:str="",sender_privateKey:str=""):
        transac = {'sender': sender,
                   'receiver': receiver,
                   'amount': amount}
        transac_hash = self.hash(transac)
        #Added new
        trans_data_sign ="sender:"+sender+","+"receiver:"+receiver+","+"amount"+str(amount)
        #msg = b"sender:user1,receiver:user2,amount:30"
        msg = bytes(trans_data_sign, 'utf-8')
        hashValue = int.from_bytes(sha512(msg).digest(), byteorder='big')
        
        #First pass n value +"_"+then pass d value
        sender_private_key_lst =sender_privateKey.split('_')
        sender_privateKey_n = sender_private_key_lst[0]
        sender_privateKey_d = sender_private_key_lst[1]

        #Digitally Signing the Transactions
        signature = pow(hashValue, int(sender_privateKey_d,16), int(sender_privateKey_n,16))
        
        trans_address = self.hash(sender_privateKey_n)

        #End Added New
        
        # Storing Transactions in UTXO format
        tran_utxo ={}
        #sender_public_key_hash = self.hash(str(sender_credentials.public_key))
        #receiver_public_key_hash = self.hash(str(receiver_public_key))
        #tran_utxo['sender_wallet_address']=sender_credentials.bitcoin_address.decode("utf-8"),
        tran_utxo['input']={"transaction_hash":hex(hashValue),
                            "sender":sender,
                            "transaction_address": trans_address, 
                            "signature": hex(signature)}                #sender signature
        #print(tran_utxo['input'])
        
        tran_utxo['output']={"amount": amount,  #amount
                             "receiver":receiver }
        
        # To store the transactions in the UTXO format if specified
        if(transaction_type == "UTXO"):
            self.transactions.append(tran_utxo)
            self.store_transactions_mempool(tran_utxo)

            
            #Broadcast Transactions from memory pool to all the nodes
            self.broadcast_transactions()
            
            #If length of transactions is greater than four, then mine block based on consensus and leader selection
            if(len(self.transactions)>=2):
                # Mine Block
                print("Transactions > 2")
                ismined = self.miner_leaderSelection()
                if(ismined):
                    print ("Blockchain mined successfully")
                    #print("Yes",ismined)
                else:
                    print("Invalid Transaction")
                    return ("Invalid Transaction")
                    
                 
        else:
            # To store the transactions in the normal format
            self.transactions.append({
            'sender':sender,
            'receiver':receiver,
            'amount': amount,
            'signature': hex(signature),
            'transaction_hash':transac_hash
            })
 
    
        previous_block = self.get_previous_block()
        if(previous_block == 0):
            return 0
        else:
            return previous_block['header']['index'] + 1
    
    # For adding a node for P2P connection
    def add_node(self, address):
        parsed_url = urlparse(address)
        self.nodes.add(parsed_url.netloc)
    
    # For broadcasting transactions from memory pool to all the miners
    def broadcast_transactions(self):
        list_transactions = []
        sql = "SELECT * FROM Trans_Mem_Pool;"
        mycursor.execute(sql)
        mytrans_mem_pool = mycursor.fetchall()
        if(len(mytrans_mem_pool)>0):
            # Append the values in the transactions list
            pass
            for i in mytrans_mem_pool:
                transation_data ={
                    'input':{"transaction_hash": i[3],  
                             "sender":i[1],
                             #"sender_public_key": sender_public_key_hash, 
                             "transaction_address":i[4],
                             "signature": i[5]},
                    'output':{"amount": i[0],  #amount
                              "receiver":i[2]
                              #"receiver_public_key": receiver_public_key_hash
                              }
                    }
                list_transactions.append(transation_data)
            self.transactions = list_transactions
            print('Transactions broadcasted to all the miners \n')
            return True
        
        else:
            print("Transaction MemPool is empty")
            return False
   
    
    # For new user Wallet Initialization
    def user_wallet_initialization(self,user_name):
        user_key = initialize_Wallet_Credentials(user_name)
        #print(len(self.user))
        self.user.append(user_key)
        return user_key
    
    # For verifying transaction signature while mining the block  
    def verify_signature(sender,transHash, signature):
        sender_publicKey_e=""
        sender_publicKey_n=""
        #Sender_publicKey Extract from Table
        sql = "SELECT * FROM Users WHERE userName = %s"   
        adr =(sender,)
        mycursor.execute(sql, adr)
        myresult = mycursor.fetchall()
        
        if(len(myresult)>0):
            for each in myresult:
                val = each[2]
                lst = val.split('_')
                sender_publicKey_n =lst[0]
                sender_publicKey_e = lst[1]
                
        hashFromSignature = pow(signature, int(sender_publicKey_e,16), int(sender_publicKey_n,16))
        if(int(transHash,16) == hashFromSignature):
            print("Transaction Valid")
            return True
        else:
            return False
        
    
    #To get the senderWalletData:
    def getSenderData(self,sender):
        walletAmount = 0
        #Sender_publicKey Extract from Table
        sql = "SELECT * FROM Users WHERE userName = %s"   
        adr =(sender,)
        mycursor.execute(sql, adr)
        myresult = mycursor.fetchall()
        
        if(len(myresult)>0):
            for each in myresult:
                walletAmount = each[3]
        return float(walletAmount)
    
    #For Validating Transaction Amount
    def validate_transactions_amount(self):
        valid_key  =True
        if(len(self.transactions)==0):
             return valid_key
        
        for i in range(len(self.transactions)):
            sender = self.transactions[i]['input']['sender']
            amount = float(self.transactions[i]['output']['amount'])
            transHash = self.transactions[i]['input']['transaction_hash']
            walletAmount = self.getSenderData(sender)
            
            if(walletAmount<amount):
                # Delete Transaction From Transaction_Memory_Pool
                print("Deleting Invalid Transaction from Memory Pool")
                sql = "DELETE FROM Trans_Mem_Pool WHERE tm_transHash = %s"   
                adr =(transHash,)
                mycursor.execute(sql, adr)
                print(mycursor.rowcount, "records deleted from Transaction Memory Pool with transaction Hash: ",
                      transHash)
                mydb.commit()
                valid_key =  False
        
        return valid_key
        
    
    # To validate the transactions while mining whether the transaction is valid or not
    def validate_transactions(self):
        valid_key  =True
        if(len(self.transactions)==0):
             return valid_key
        
        #receiver_credentials = None
        
        for i in range(len(self.transactions)):
            #verify digital signature
            try:
                valid_key = self.verify_signature(self.transactions[i]['input']['sender'],
                                     self.transactions[i]['input']['transaction_hash'],
                                     self.transactions[i]['input']['signature'])
                print("Transaction_Valid: ",valid_key)
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
    #print("previous_block",previous_block)
    if(previous_block == 0):
        previous_proof = 0
        previous_hash = 0
    else:
        
        previous_proof = previous_block['header']['proof']
        previous_hash =  previous_block['header']['block_hash']
        #previous_hash = blockchain.hash(previous_block)
    
    proof = blockchain.proof_of_work(previous_proof)
    
    
    #Broadcast all the transactions in the mempool to all the miners
    blockchain.broadcast_transactions()
    
    
    isAmountValid = True
    #Validate Transaction Amount
    isAmountValid = blockchain.validate_transactions_amount()
    
    #Validate Signature
    is_valid = blockchain.validate_transactions()
    if(not is_valid ):
        response = {'message': 'Error Occurred: Transactions are not digitally verified'}
        return jsonify(response), 200
    elif(isAmountValid == False):
        response = {'message': 'Error Occurred: Not Sufficient Amount in the Wallet for transfer'}
        return jsonify(response), 400
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
    transaction_keys = ['sender', 'receiver', 'amount','sender_privateKey']
    if not all(key in json for key in transaction_keys):
        return 'Some elements of the transaction are missing', 400
    
      
    # Transaction type has been specified as "UTXO" - if not mentioned will have normal header and body
    index = blockchain.add_transaction(json['sender'], json['receiver'], json['amount'],
                                       transaction_type="UTXO",
                                       sender_privateKey=json['sender_privateKey'])
    
    if(index == "Invalid Transaction"):
        response = {'message': 'Invalid Transaction: Block Cannot be Mined. Invalid Transactions will be deleted.'}
    else:
        response = {'message': 'This transaction will be added to the new Block in the Blockchain'}
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
    response={}
    if not all(key in json for key in user_keys):
        return 'Some elements of the user login are missing', 400
    

    #Check if user is already in database, if present -> skip initialization, else do user's wallet initialization
    #Checking user in the database
    
    sql = "SELECT * FROM Users WHERE userName = %s"   
    adr =(json['user_name'],)
    print(json['user_name'])
    mycursor.execute(sql, adr)
    
    myresult = mycursor.fetchall()
    #print("user_login_result",myresult)
    
    if(len(myresult)>0):
        
        #If user already registered no need to insert into table again
        u_name= ""
        u_pub_key=""
        
        for x in myresult:
          #print(x)
          u_name = x[1]
          u_pub_key = x[2]
          
        response = {'message':"User Successfully connected to the blockchain network",
                    'user_name': u_name,
                    'user_public_key':u_pub_key
                   }

    else:
        # New User Login
        user = blockchain.user_wallet_initialization(json['user_name'])
        # Insert user details into database
        u_public_key = hex(user.public_key.n)+"_"+hex(user.public_key.e)
        #print("Public_key: ",u_public_key)
        sql = "INSERT INTO Users (userName, userPublicKey,userWalletAmount) VALUES (%s, %s, %s)"
        val = (user.user_name, u_public_key,user.wallet_amount)
        mycursor.execute(sql, val)
        print(mycursor.rowcount, "record inserted in user's table.")
        mydb.commit()
        
        """
        print("User's user name: ", user.user_name)
        print(f"User's  Public key:  (n={hex(user.public_key.n)}, e={hex(user.public_key.e)})")
        print(f"User's  Private key: (n={hex(user.private_key.n)}, d={hex(user.private_key.d)})")
        print("User's wallet address:", user.bitcoin_address)
        print("User's Wallet amount: ",user.wallet_amount)
        """
        
        #print("*******************************************************************")
        response ={'user_name':user.user_name,
                   #'user_public_key':str(user.public_key),
                   'user_private_key':f"(n={hex(user.private_key.n)}, d={hex(user.private_key.d)})",
                   'user_public_key':f"(n={hex(user.public_key.n)}, e={hex(user.public_key.e)})",
                   'message':"User's Wallet Created Successfully. Do not share your Private Key with anyone. Now you are successfully connected to the blockchain network"
                   }
    return jsonify(response), 200


#Part 6: Get Information from database

# Getting the full Blockchain
@app.route('/get_chain', methods = ['GET'])
def get_chain():
    sql = "SELECT * FROM Blocks;"   
    mycursor.execute(sql)
    myresult = mycursor.fetchall()
    blockData =[]
    _,_,blockData = response_block_data_db(myresult)

    #blockchain.getLatestBlockChain()
    
    if(len(blockData) == 0):
        response = {'message': "The blockchain is empty."}
    else:
        response = {'chain': blockData,
                    'length': len(blockData)}
    return jsonify(response), 200
  
# Que1:  To get Genesis transaction: to find the (Genesis) block hash from the transaction hash
    
@app.route('/get_genesis_transation', methods = ['POST'])
def get_genesis_transation():
    json = request.get_json()
    response ={}
    #sql = "SELECT * FROM Blocks b INNER Join Transactions t ON b.blockIndex = t.blockIndex and t.transHash = %s"   
    
    sql = "SELECT * FROM Blocks order by blockIndex ASC LIMIT 1";
    #adr =(json['transaction_hash'],)
    print("Query Transation Hash:", json['transaction_hash'])
    print("**************************************************")
    #mycursor.execute(sql, adr)
    mycursor.execute(sql)
    
    myresult = mycursor.fetchall()    
    if(len(myresult)>0):      
        for x in myresult:
            block_data={
                'block_Index':x[0],
                'block_MerkleRoot':x[1],
                'block_PreviousHash':x[2],
                'block_Proof':x[3],
                'block_Hash':x[4],
                'block_TimeStamp':str(x[5])}
            response = {'Genesis Block Data':block_data
                       }
    return jsonify(response), 200
    

#Que2: To find the addresses and amounts of the transactions
@app.route('/get_transaction_data_db', methods = ['GET'])
def get_transaction_data_db():
    response ={}
     
    sql = "SELECT * FROM Transactions;";
    mycursor.execute(sql)
    
    myresult = mycursor.fetchall()
    #print("user_login_result",myresult)
    response = {}
    trans_data_db =[]
    if(len(myresult)>0):      
        for x in myresult:
            transation_data={
                #'sender':x[3],
                #'receiver':x[4],
                'transaction_amount':x[2],
                'transaction_hash':x[5],
                'transaction_address':x[6]
                }
            trans_data_db.append(transation_data)
        
        response = {'Transaction Data':trans_data_db
                       }      
    return jsonify(response), 200

#Que3: To show the block information of the block with the hash address of (input the hash of the block)

@app.route('/get_block_data_from_hash', methods = ['POST'])
def get_block_data_from_hash():
    json = request.get_json()
    response ={}
     
    sql = "SELECT * FROM Blocks where blockHash = %s"   
    adr =(json['block_hash'],)
    mycursor.execute(sql, adr)
    myresult = mycursor.fetchall()  
    
    block_header={}
    block_body={}
    blockData =[]
    block_header,block_body,blockData= response_block_data_db(myresult)
    response = {'message': 'Block Data for the given block_hash:',
                'header':block_header,
                'body':block_body}
        
    return jsonify(response), 200

#Que4: To show the height of the most recent block stored
@app.route('/get_block_height', methods = ['GET'])
def get_block_height():
    #json = request.get_json()
    response ={}
     
    sql = "select blockIndex-1,blockIndex from Blocks order by blockIndex Desc LIMIT 1;";
    #mycursor.execute(sql, adr)
    mycursor.execute(sql)
    myresult = mycursor.fetchall()
    #print("user_login_result",myresult)
    response = {}
    blockHeight =""
    blockIndex_ =""
    if(len(myresult)>0):      
        for x in myresult:
            blockHeight =x[0]
            blockIndex_ =x[1]
            
        response = {'Height of the most recent block stored':blockHeight,
                    'Block Index of the most recent block stored':blockIndex_
                       }
            
    return jsonify(response), 200

#Que5:To show the most recent block stored.
@app.route('/get_most_recent_block', methods = ['GET'])
def get_most_recent_block():
    response ={}
    sql = "select * from Blocks order by blockIndex Desc LIMIT 1;";
    mycursor.execute(sql)
    myresult = mycursor.fetchall()
    block_header={}
    block_body={}
    blockData =[]
    block_header,block_body,blockData= response_block_data_db(myresult)
    
    response = {'message': 'Block Data of the most recent stored block:',
                'header':block_header,
                'body':block_body}
        
    return jsonify(response), 200

#Que6:To find the average number of transactions per block in the entire Bitcoin blockchain
@app.route('/get_avg_transactions_per_block', methods = ['GET'])
def get_avg_transactions_per_block():
    response ={}
    sql = "select AVG(blockTransCount) from Blocks;"
    mycursor.execute(sql)
    myresult = mycursor.fetchall()
    response = {}
    avg_trans = 0
    if(len(myresult)>0):      
        for x in myresult:
            avg_trans =x[0]
    response = {'Average number of transactions per block in the entire blockchain':avg_trans
               }
    return jsonify(response), 200

#Que7: To show a summary report of the transactions in the block with height 6
@app.route('/get_block_transactions_summary', methods = ['POST'])
def get_block_transactions_summary():
    json = request.get_json()
    response ={}
    no_transaction_for_block=0
    total_input_bitcoins_for_block=0
     
    sql = "SELECT * FROM Blocks where blockIndex = %s"   
    adr =(int(json['block_height'])+1,)
    mycursor.execute(sql, adr)
    myresult = mycursor.fetchall()  

    
    if(len(myresult)>0):
        for each in myresult:
            no_transaction_for_block = each[6]
            
    sql = "SELECT sum(transAmount) from transactions where blockIndex  = %s"   
    adr =(int(json['block_height'])+1,)
    mycursor.execute(sql, adr)
    myresult = mycursor.fetchall()
    if(len(myresult)>0):
        for each in myresult:
            total_input_bitcoins_for_block = each[0]
             
    
    response = {'message': 'summary report of the transactions in the block with given height :',
                'Number of transactions for the given block':no_transaction_for_block,
                'block_height':json['block_height'],
                'Total input Bitcoins for the given block':total_input_bitcoins_for_block}
        
    return jsonify(response), 200
    
# Running the app
app.run(host = '0.0.0.0', port = 5001)
