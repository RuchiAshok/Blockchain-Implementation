Attached Code file: "M21MA004_Code" contains all the codes for all the parts given in the assignment in a single code file. 

Report_Blockchain: contains a brief report on how the blockchain is working

*******************************************************************************************************************************
1. To Create at least 10 nodes as miners who are connected to each other we need to replicate same set of codes and run each at 
10 different ports by changing the port number from 5001 to 5010 at the end of the file.
Also need to change the port number for specific files in the "miner_leaderSelection" function.

To Connect nodes to each other:
	[POST] API: http://0.0.0.0:5001/connect_node
	Param to be passed in the body:
	{
    	"nodes":["http://127.0.0.1:5002",
            "http://127.0.0.1:5003",
            "http://127.0.0.1:5004",
            "http://127.0.0.1:5005",
            "http://127.0.0.1:5006",
            "http://127.0.0.1:5007",
            "http://127.0.0.1:5008",
            "http://127.0.0.1:5009",
            "http://127.0.0.1:50010"]
	}
	

Likewise we can connect other nodes to each other (by chaning the port number).

To Connect a User to a miner node (say miner at node1 port:5001)
	[POST] API: http://0.0.0.0:5001/user_connect
	Param to be passed in the body:
	{
    	"user_name":"user1"
    	}
	
On connecting the users to the node, their wallet will be initialized as well.
Likewise we can connect users to another miner node (by chaning the port number).

*******************************************************************************************************************************
2. To get the blockchain
	[GET] API:http://0.0.0.0:5001/get_chain
	If the blockchain is empty it will create a Genesis Block on calling the API

*******************************************************************************************************************************
3. To add a transaction
	[POST] API: http://0.0.0.0:5001/add_transaction
	Param to be passed in the body:
	{
    	"sender":"user1",
    	"receiver":"user2",
    	"amount":50
	}
	NOTE1: Transactions can be created between the user's for whom wallet has been initialized.
	NOTE2: After creation of 4 transactions, automatically as per the logic implemented the block will be mined by miner 
	selected using leader selection between all the connected miner nodes and consensus algorithm implemented is POW.

*******************************************************************************************************************************
4. If any miner manually wants to mine block (should not be done at all, written only for testing purpose) 
	[GET] API: http://0.0.0.0:5001/mine_block

*******************************************************************************************************************************
5. To check if the blockchain is valid or not ( for testing purpose)
	[GET] API: http://0.0.0.0:5001/is_valid

*******************************************************************************************************************************
Refer attached report for working of the blockchain.