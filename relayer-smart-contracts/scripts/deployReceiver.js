// Import the Hardhat Runtime Environment
const { ethers } = require("hardhat");
require('dotenv').config();

const { TRUSTED_RELAYER_PUBLIC_ADDRESS } = process.env;

async function main() {
    const [deployer] = await ethers.getSigners();

    console.log("Deploying contracts with the account:", deployer.address);

    // Get the contract factory for the SendMessenger contract
    const ReceiveMessenger = await ethers.getContractFactory("MessengeReceiver");

    // Deploy the contract
    const receiveMessenger = await ReceiveMessenger.deploy(TRUSTED_RELAYER_PUBLIC_ADDRESS);

    // Wait for the deployment to be mined
    await receiveMessenger.deploymentTransaction().wait();

    // Log the address of the deployed contract
    console.log("ReceiveMessenger deployed to:", receiveMessenger.address);
    console.log(receiveMessenger);
}

// Execute the main function and handle errors
main()
    .then(() => process.exit(0)) // Exit the process with success
    .catch((error) => {
        console.error(error); // Log any errors
        process.exit(1); // Exit the process with failure
    });