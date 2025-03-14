//SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";


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


    // A signature function to cryptographically sign the message to improve the security - TODO
    function createSignature() internal pure returns(bytes memory) {
        return "";
    }

    function verifySignature() internal pure returns (bool) {
        return true;
    }

    function sendMessage(string memory _message, Chains _targetChain) external {
        bytes32 messageId = keccak256(abi.encodePacked(
            msg.sender,
            bytes(_message),
            block.timestamp,
            nonce
        ));

        bytes memory _signature = createSignature();

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
        bytes32 messageId
        // To add more parameters
    ) external {
        
        require(messages[messageId].processed == false, "message-id-already-processed");
        // verify signature in the message from the sender - TODO
        
        messages[messageId].processed = true;
        bytes memory _signature = createSignature();
        
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