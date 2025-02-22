require("@nomicfoundation/hardhat-toolbox");
require('dotenv').config();

const { ALCHEMY_ARBITRUM_SEPOLIA_RPC, ALCHEMY_SEPOLIA_RPC, PRIVATE_KEY_SEPOLIA, PRIVATE_KEY_ARBITRUM } = process.env;

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: "0.8.28",
  networks: {
    sepolia: {
        url: ALCHEMY_SEPOLIA_RPC,
        accounts: [`0x${PRIVATE_KEY_SEPOLIA}`]
      },
    arbitrum: {
      url: ALCHEMY_ARBITRUM_SEPOLIA_RPC,
      accounts: [`0x${PRIVATE_KEY_ARBITRUM}`]
    }
  }
};
