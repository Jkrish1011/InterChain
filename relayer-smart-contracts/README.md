# InterChain Smart Contracts

This project contains the smart contracts which can be deployed on ethereum based chains to emit events.


1. MessageReceiver.sol
This smart contract receives messages from the relayer and emits the "ACK" event

2. MessageSender.sol
This smart contract initiates the handshake by sending out the "SYN" message.


## Deployment of Sender Contract

```shell
npx hardhat compile
npx hardhat run scripts/deploySender.js --network sepolia
```

## Deployment of Receiver Contract

```shell
npx hardhat compile
npx hardhat run scripts/deployReceiver.js --network arbitrum
```

## Emit "SYN" Message
```shell
npx hardhat run scripts/testSendMessage.js --network sepolia
```

## Emit "ACK" Message
```shell
npx hardhat run scripts/testReceiveMessage.js --network arbitrum
```

