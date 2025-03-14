const { ethers, upgrades } = require("hardhat");
require('dotenv').config();

const { TRUSTED_RELAYER_PUBLIC_ADDRESS } = process.env;

async function main() {
    const [deployer] = await ethers.getSigners();

    console.log("Deploying contracts with the account:", deployer.address);

    // Deploy the implementation contract
    const InterChainEthereumMessenger = await ethers.getContractFactory("InterChainEthereumMessenger");
    console.log("Deploying InterChainEthereumMessenger...");

    const interChainEthereumMessenger = await upgrades.deployProxy(InterChainEthereumMessenger, [TRUSTED_RELAYER_PUBLIC_ADDRESS], {
        initializer: "initialize",
    });

    const deploymentReceipt = await interChainEthereumMessenger.deploymentTransaction().wait();

    console.log({deploymentReceipt});
    // Get the transaction hash and block number
    // console.log("Transaction hash:", deploymentReceipt.hash);
    // console.log("Block number:", deploymentReceipt.blockNumber);

    // Get the proxy address
    const proxyAddress = interChainEthereumMessenger.deploymentReceipt.contractAddress;
    console.log("Proxy deployed to:", proxyAddress);

    // const proxyAddress = "0x55751a089Ec272595E61980772EEC0a9117Da4f5";

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