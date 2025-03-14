// Import necessary libraries
const { ethers } = require("hardhat");
require('dotenv').config();

const { ARBITRUM_SEPOLIA_CONTRACT_ADDRESS } = process.env;

function generateRandomString(length) {
    let result = '';
    let characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

async function main() {
    
    const contractAddress = ARBITRUM_SEPOLIA_CONTRACT_ADDRESS;

    // Create a new instance of the contract
    const InterChainArbMessengerContract = await ethers.getContractFactory("InterChainArbitrumMessenger");
    const arbMessenger = InterChainArbMessengerContract.attach(contractAddress);

    // Prepare the parameters for the receiveMessage function
    const messageId = ethers.encodeBytes32String(generateRandomString(5)); // Example message ID
    const timestamp = Math.floor(Date.now() / 1000); // Current timestamp

    // Get the signer for the trusted relayer
    const [signer] = await ethers.getSigners();
    console.log(`signer::address - ${signer.address}`);
    // console.log({TRUSTED_RELAYER_PUBLIC_ADDRESS});

    // Call the trustedRelayer public variable
    // const trustedRelayer = await arbMessenger.trustedRelayer();

    // console.log(`Trusted Relayer Address: ${trustedRelayer}`);

    // Ensure the signer is the trusted relayer
    // if (signer.address != trustedRelayerAddress) {
    //     console.error("Signer is not the trusted relayer");
    //     return;
    // }

    console.log({messageId});
    // Call the receiveMessage function
    const tx = await arbMessenger.receiveMessage(messageId, signer, timestamp, 0);
    
    // Wait for the transaction to be mined
    await tx.wait();

    console.log("Tx hash:", tx.hash);
}

// Execute the main function
main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error);
        process.exit(1);
    });