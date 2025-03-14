//SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";


contract InterChainArbitrumMessenger is Initializable {

    
    // -------------------------------------- DECLARATIONS --------------------------------------
    mapping(bytes32 => bool) public processedMessages;
    
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

    modifier onlyTrustedRelayer() {
        require(msg.sender == trustedRelayer, "only-trusted-relayer-can-relay-messages");
        _;
    }

    // -------------------------------------- EVENTS --------------------------------------
    
    event InterChainArbitrumMessage(
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

    function receiveMessage(
        bytes32 messageId,
        address sender,
        uint256 timestamp,
        Chains receivedFromChain
    ) external {

        require(!processedMessages[messageId], "message-already-processed");
        // require() // signature should be verified - TODO

        processedMessages[messageId] = true;
        bytes memory _signature = createSignature();
        emit InterChainArbitrumMessage(messageId, sender, bytes("ACK"), timestamp, _signature, receivedFromChain);
    }
}