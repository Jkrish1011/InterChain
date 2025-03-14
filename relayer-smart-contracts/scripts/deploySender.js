// Import the Hardhat Runtime Environment
const { ethers } = require("hardhat");
require('dotenv').config();

const { TRUSTED_RELAYER_PUBLIC_ADDRESS } = process.env;

async function main() {
    // Get the contract factory for the SendMessenger contract
    const SendMessenger = await ethers.getContractFactory("InterChainEthereumMessenger");
    
    // Deploy the contract
    const sendMessenger = await SendMessenger.deploy(TRUSTED_RELAYER_PUBLIC_ADDRESS);

    // Wait for the deployment to be mined
    await sendMessenger.deploymentTransaction().wait();

    // Log the address of the deployed contract
    console.log("SendMessenger deployed to:", sendMessenger.address);
    console.log(sendMessenger);
}

// Execute the main function and handle errors
main()
    .then(() => process.exit(0)) // Exit the process with success
    .catch((error) => {
        console.error(error); // Log any errors
        process.exit(1); // Exit the process with failure
    });