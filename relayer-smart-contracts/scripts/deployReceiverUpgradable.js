const { ethers, upgrades } = require("hardhat");
require('dotenv').config();

const { TRUSTED_RELAYER_PUBLIC_ADDRESS } = process.env;

async function main() {
    const [deployer] = await ethers.getSigners();

    console.log("Deploying contracts with the account:", deployer.address);

    // Deploy the implementation contract
    const MessengeReceiver = await ethers.getContractFactory("MessengeReceiver");
    console.log("Deploying MessengeReceiver...");

    const messengeReceiver = await upgrades.deployProxy(MessengeReceiver, [TRUSTED_RELAYER_PUBLIC_ADDRESS], {
        initializer: "initialize",
    });

    const deploymentReceipt = await messengeReceiver.deploymentTransaction().wait();

    console.log({deploymentReceipt});
    // Get the transaction hash and block number
    // console.log("Transaction hash:", deploymentReceipt.transactionHash);
    // console.log("Block number:", deploymentReceipt.blockNumber);

    // Get the proxy address
    const proxyAddress = messengeReceiver.deploymentReceipt.contractAddress;
    console.log("Proxy deployed to:", proxyAddress);

    // const proxyAddress = "0x1b6c07cd43D5a6EA384eC90dcCbF8d284964C7f7";

    // Get the implementation address
    const implementationAddress = await upgrades.erc1967.getImplementationAddress(proxyAddress);
    console.log("Implementation deployed to:", implementationAddress);

    // Get the admin address
    const adminAddress = await upgrades.erc1967.getAdminAddress(proxyAddress);
    console.log("Admin address:", adminAddress);


}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error);
        process.exit(1);
    });