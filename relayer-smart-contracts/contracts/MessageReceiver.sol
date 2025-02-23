//SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";


contract MessengeReceiver is Initializable {
    // -------------------------------------- EVENTS --------------------------------------
    
    event MessageReceived(
        bytes32 indexed messageId,
        address indexed sender,
        bytes message,
        uint256 timestamp
    );
    
    // -------------------------------------- DECLARATIONS --------------------------------------
    
    mapping(bytes32 => bool) public processedMessages;
    
    // Address of the trusted relayer
    address public trustedRelayer;

    modifier onlyTrustedRelayer() {
        require(msg.sender == trustedRelayer, "only-trusted-relayer-can-relay-messages");
        _;
    }

    // -------------------------------------- FUNCTIONS --------------------------------------

    // constructor(address _trustedRelayer) {
    //     trustedRelayer = _trustedRelayer;
    // }

    function initialize(address _trustedRelayer) public initializer {
        trustedRelayer = _trustedRelayer;
    }

    function verifySignature() internal pure returns (bool) {
        return true;
    }

    function receiveMessage(
        bytes32 messageId,
        address sender,
        uint256 timestamp
    ) external {

        require(!processedMessages[messageId], "message-already-processed");
        // require() // signature should be verified - TODO

        processedMessages[messageId] = true;
        emit MessageReceived(messageId, sender, bytes("ACK"), timestamp);
    }
}