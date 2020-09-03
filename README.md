## Genesis Block Proof of Work for Groestlcoin.

>> Node.js version --> https://github.com/Groestlcoin/node-genesis-block


## setup

```js
sudo pip install groestlcoin_hash construct==2.5.2

git clone https://github.com/Groestlcoin/genesis-block.git

cd genesis-block

```

## help

```js
Usage: gen.py [options]

  Options:
    -h, --help show this help message and exit
    -t TIME, --time=TIME  the (unix) time when the genesisblock is created
    -z TIMESTAMP, --timestamp=TIMESTAMP
       the pszTimestamp found in the coinbase of the genesisblock
    -n NONCE, --nonce=NONCE
       the first value of the nonce that will be incremented
       when searching the genesis hash
    -a NET, --net=NET
       the network: [mainnet|testnet|regtest]
    -p PUBKEY, --pubkey=PUBKEY
       the pubkey found in the output script
    -v VALUE, --value=VALUE
       the value in coins for the output, full value (exp. in groestlcoin 0 - To get other value: Block Value * 100000000)
    -b BITS, --bits=BITS
       the target in compact representation, associated to a difficulty of 1
```

## Genesis Block Proof of Work for Mainnet.

```js
python gen.py -a mainnet -n 220035 -t 1395342829

```


## Genesis Block Proof of Work for Testnet.

```js
python gen.py --a testnet -n 6556309 -t 1440000002

```

## Genesis Block Proof of Work for Regtest.

```js
python gen.py -a regtest -n 6556309 -t 1440000002

```
