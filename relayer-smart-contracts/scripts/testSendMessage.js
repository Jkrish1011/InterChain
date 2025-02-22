const { ethers } = require("hardhat");
require('dotenv').config();

const { SEPOLIA_CONTRACT_ADDRESS } = process.env;

async function main() {
    const contractAddress = SEPOLIA_CONTRACT_ADDRESS; 
    const [signer] = await ethers.getSigners();
    console.log(`signer::address - ${signer.address}`);
    // Get the contract factory for the SendMessenger contract
    const SendMessenger = await hre.ethers.getContractFactory("MessengeSender");

    // Re-instantiate the contract using the deployed address
    const sendMessenger = SendMessenger.attach(contractAddress);

    // Define the message you want to send
    const message = "SYN";

    // Call the sendMessage function
    const tx = await sendMessenger.sendMessage(message);

    // Wait for the transaction to be mined
    await tx.wait();

    console.log("Tx hash:", tx.hash);
}

main()
    .then(() => process.exit(0)) 
    .catch((error) => {
        console.error(error); 
        process.exit(1);
    });