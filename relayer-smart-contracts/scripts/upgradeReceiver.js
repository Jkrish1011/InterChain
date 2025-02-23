const { ethers, upgrades } = require("hardhat");
require('dotenv').config();

const { ARBITRUM_CONTRACT_ADDRESS } = process.env;

async function main() {
    console.log("Upgrading proxy at:", ARBITRUM_CONTRACT_ADDRESS);

    // Deploy the new implementation contract
    const MessengeReceiverV2 = await ethers.getContractFactory("MessengeReceiver");
    const upgraded = await upgrades.upgradeProxy(proxyAddress, MessengeReceiverV2);

    console.log("Proxy upgraded to V2 at:", upgraded.contractAddress);

    // Get the new implementation address
    const newImplementationAddress = await upgrades.erc1967.getImplementationAddress(ARBITRUM_CONTRACT_ADDRESS);
    console.log("New implementation deployed to:", newImplementationAddress);

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