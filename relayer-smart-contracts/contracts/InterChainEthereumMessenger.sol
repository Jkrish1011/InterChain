//SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";


contract InterChainEthereumMessenger is Initializable {
    // -------------------------------------- DECLARATIONS --------------------------------------
    
    // Address of the trusted relayer   
    address public trustedRelayer;

    // Enum to list all supported chains
    enum Chains {
        Ethereum,
        Polygon,
        Arbitrum,
        Optimism,
        Base,
        Avalanche,
        BSC,
        Gnosis 
    }
    
    // To prevent replay attacks
    uint256 private nonce;

    struct Message {
        bytes32 messageId;
        address sender;
        bytes message;
        uint256 timestamp;
        bytes signature;
        bool processed;
        Chains targetChain;
    }

    // A mapping to track/store all messages passed.
    mapping(bytes32 => Message) public messages;

    modifier onlyTrustedRelayer() {
        require(msg.sender == trustedRelayer, "only-trusted-relayer-can-relay-messages");
        _;
    }

    // -------------------------------------- EVENTS --------------------------------------

    // Event to Notify relayer that the message has been initiated.
    event InterChainEthereumMessage(
        bytes32 indexed messageId,
        address indexed sender,
        bytes message,
        uint256 timestamp,
        bytes signature,
        Chains targetChain
    );

    // -------------------------------------- FUNCTIONS --------------------------------------

    // constructor(address _trustedRelayer) {
    //     trustedRelayer = _trustedRelayer;
    // }

    function initialize(address _trustedRelayer) public initializer {
        trustedRelayer = _trustedRelayer;
    }

    function verifySignature(string memory _message, Chains _targetChain, bytes memory _signature) internal view returns (bool) {
        bytes32 messageHash = keccak256(abi.encodePacked(
            bytes(_message),
            uint256(_targetChain)
        ));

        bytes32 ethSignedMsgHash = MessageHashUtils.toEthSignedMessageHash(messageHash);        
        address recoveredSignerAddress = ECDSA.recover(ethSignedMsgHash, _signature);

        require(recoveredSignerAddress == msg.sender, "invalid-signature");

        return true;
    }

    function sendMessage(string memory _message, Chains _targetChain, bytes memory _signature) external {

        require(verifySignature(_message, _targetChain,_signature), "invalid-signature");

        bytes32 messageId = keccak256(abi.encodePacked(
            msg.sender,
            bytes(_message),
            block.timestamp,
            nonce,
            _signature
        ));

        messages[messageId] = Message({
            messageId: messageId,
            sender: msg.sender,
            message: bytes(_message),
            timestamp: block.timestamp,
            signature: _signature,
            processed: false,
            targetChain: _targetChain
        });

        emit InterChainEthereumMessage(
            messageId,
            msg.sender,
            bytes(_message),
            block.timestamp,
            _signature,
            _targetChain
        );
        
        nonce++;
    }

    function ackMessage(
        bytes32 messageId,
        bytes memory _signature
    ) external {
        
        require(messages[messageId].processed == false, "message-id-already-processed");
        require(verifySignature(string(messages[messageId].message), messages[messageId].targetChain, _signature), "invalid-signature");
        
        messages[messageId].processed = true;
        
        emit InterChainEthereumMessage(
            messageId,
            msg.sender,
            bytes("SYN-ACK"),
            block.timestamp,
            _signature,
            messages[messageId].targetChain
        );
    }
}