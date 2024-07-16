# DRPoP-GT: Delegated Reputation based Proof of Probability using Game Theory

The work focuses on applying game theory to blockchain technology. The goal is to analyze and optimize the behavior and interactions of various participants within the blockchain ecosystem. By modeling actions of miners, validators, and other stakeholders as strategic games, we incentivize honest behavior and deter malicious activities. This ensures consensus, security, and efficiency in blockchain operations, particularly in Proof of Stake and Proof of Work systems. Here, the Game Theory is integrated to Proof of Stake consensus algorithm. The DRPoP-GT consensus algorithm is evaluated using performance metrics across various scenarios and experimental parameters.

---------

## Implementation

We have implemented a multi-node configuration of Ethereum by incorporating the DRPoP-GT consensus mechanism. Specifically, we focused on the ethash files and used the Go programming language to develop our new consensus algorithm. In this new approach, we replaced the code of the PoS consensus mechanism with our implementation, which involves filtering out the nodes, two-stage game, penalizing the nodes, and selection of miner. The initial filtering of nodes takes place based on stakes for selection of Delegated nodes. The eligible nodes are selected as delegated nodes, which then participate in a two-stage game:

1. **First-Stage Game**
2. **Second-Stage Game**

The results of the first-stage game are utilized in the second-stage game. After completing the two-stage game, the last eligible node is selected as the miner and receives rewards. A penalty is imposed at each stage if a node behaves maliciously.

---

## Below are the steps to run DRPoP-GT setup on Ubuntu:

### Step 1:
Download Ethereum files from the official website and replace the `consensus` folder in `go/src/consensus` with the one given in this repository.

### Step 2:
Create a folder `ethereum` (as a workspace) and subfolders `nodes` in the home directory where the Ethereum files downloaded must be present. We create four node folders for a four-node setup.

```bash
mkdir ethereum
cd ethereum
mkdir node1 node2 node3 node4
```

### Step 3:
Compile the Ethereum code by running the command below inside a terminal opened in the `go/src/ethereum/go-ethereum` folder and then copy the `geth` executable file from the `go/bin` folder into the `ethereum` (workspace) folder.

```bash
go install -v ./cmd/geth
```

### Step 4:
Nodes must be initialized with a unique account hash and authentication (password), functioning as participants in the system. These nodes are connected to their respective accounts. To achieve this, we used "geth," an executable file generated, which facilitates the creation and running of Ethereum nodes. Write down the public key of each node.

```bash
sudo ./geth --datadir ~/ethereum/node1 account new
sudo ./geth --datadir ~/ethereum/node2 account new
sudo ./geth --datadir ~/ethereum/node3 account new
sudo ./geth --datadir ~/ethereum/node4 account new
```

### Step 5:
Create a special file called a genesis file in a simple JSON format to initialize the blockchain. This file is created using "puppeth," a tool that helps manage private Ethereum networks. The genesis file includes the hash of the accounts and acts as an initializer for the blockchain. This file is linked to all nodes.

### Step 6:
Initialize the nodes with the genesis file.

```bash
sudo ./geth --datadir ~/ethereum/node1 init genesis.json
sudo ./geth --datadir ~/ethereum/node2 init genesis.json
sudo ./geth --datadir ~/ethereum/node3 init genesis.json
sudo ./geth --datadir ~/ethereum/node4 init genesis.json
```

### Step 7:
Generate a "boot node" to aid in the effective communication of nodes.

```bash
sudo bootnode -genkey boot.key
```

### Step 8:
Run the bootnode with the generated bootkey, which must be running in the background to help nodes stay connected in the network.

```bash
sudo bootnode -nodekey boot.key
# Example: enode://6d20dc312a4c9262a7251a68dc539db0557123309c6aae8b34bad9b1ee0afc1bf36d3be604ebec067ad7f962ec745fc2749bfcba868a01ce616542f22bafea58@127.0.0.1:0?discport=30301
```

### Step 9:
With all preparations complete, start the blockchain on each terminal representing each node, with each node using its communication channel (port). This process ensures our modified blockchain with the EPoL consensus mechanism starts up successfully. Run each of the following in separate terminals.

```bash
sudo ./geth --allow-insecure-unlock --datadir ~/ethereum/node1/ --syncmode 'full' --port 30311 --rpc --rpcaddr 'localhost' --rpcport 8501 --rpcapi 'personal,db,eth,net,web3,txpool,miner' --bootnodes 'enode://<bootnode_enode>@127.0.0.1:0?discport=30301' --networkid 1515 --gasprice '1' --mine console
```

```bash
sudo ./geth --allow-insecure-unlock --datadir ~/ethereum/node2/ --syncmode 'full' --port 30312 --rpc --rpcaddr 'localhost' --rpcport 8502 --rpcapi 'personal,db,eth,net,web3,txpool,miner' --bootnodes 'enode://<bootnode_enode>@127.0.0.1:0?discport=30301' --networkid 1515 --gasprice '1' --mine console
```

```bash
sudo ./geth --allow-insecure-unlock --datadir ~/ethereum/node3/ --syncmode 'full' --port 30313 --rpc --rpcaddr 'localhost' --rpcport 8503 --rpcapi 'personal,db,eth,net,web3,txpool,miner' --bootnodes 'enode://<bootnode_enode>@127.0.0.1:0?discport=30301' --networkid 1515 --gasprice '1' --mine console
```

```bash
sudo ./geth --allow-insecure-unlock --datadir ~/ethereum/node4/ --syncmode 'full' --port 30314 --rpc --rpcaddr 'localhost' --rpcport 8504 --rpcapi 'personal,db,eth,net,web3,txpool,miner' --bootnodes 'enode://<bootnode_enode>@127.0.0.1:0?discport=30301' --networkid 1515 --gasprice '1' --mine console
```

### Step 10:
The Geth console will be active for each node, allowing you to interact with the Ethereum network.

---





