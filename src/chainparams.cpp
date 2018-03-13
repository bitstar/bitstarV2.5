// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

#include "chainparamsseeds.h"

using namespace std;

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    // Genesis block

    // MainNet:

    //CBlock(hash=000001faef25dec4fbcf906e6242621df2c183bf232f263d0ba5b101911e4563, ver=1, hashPrevBlock=0000000000000000000000000000000000000000000000000000000000000000, hashMerkleRoot=12630d16a97f24b287c8c2594dda5fb98c9e6c70fc61d44191931ea2aa08dc90, nTime=1393221600, nBits=1e0fffff, nNonce=164482, vtx=1, vchBlockSig=)
    //  Coinbase(hash=12630d16a9, nTime=1393221600, ver=1, vin.size=1, vout.size=1, nLockTime=0)
    //    CTxIn(COutPoint(0000000000, 4294967295), coinbase 00012a24323020466562203230313420426974636f696e2041544d7320636f6d6520746f20555341)
    //    CTxOut(empty)
    //  vMerkleTree: 12630d16a9

    // TestNet:

    //CBlock(hash=0000724595fb3b9609d441cbfb9577615c292abf07d996d3edabc48de843642d, ver=1, hashPrevBlock=0000000000000000000000000000000000000000000000000000000000000000, hashMerkleRoot=12630d16a97f24b287c8c2594dda5fb98c9e6c70fc61d44191931ea2aa08dc90, nTime=1393221600, nBits=1f00ffff, nNonce=216178, vtx=1, vchBlockSig=)
    //  Coinbase(hash=12630d16a9, nTime=1393221600, ver=1, vin.size=1, vout.size=1, nLockTime=0)
    //    CTxIn(COutPoint(0000000000, 4294967295), coinbase 00012a24323020466562203230313420426974636f696e2041544d7320636f6d6520746f20555341)
    //    CTxOut(empty)
    //  vMerkleTree: 12630d16a9

    CMutableTransaction txNew;
    txNew.nTime = nTime;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 0 << CScriptNum(42) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].SetEmpty();

    CBlock genesis;
    genesis.vtx.push_back(txNew);
    genesis.hashPrevBlock.SetNull();
    genesis.nVersion = nVersion;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "23 aug 2017 Floyd Mayweather v Conor McGregor: Chaos at media event in Las Vegas";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG; //AAM CHECK THIS
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nMaxReorganizationDepth = 500;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.posLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.posLimitV2 = uint256S("000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nTargetTimespan = 16 * 60; // 16 mins
        consensus.nTargetSpacingV1 = 30;
        consensus.nTargetSpacing = 30;
        consensus.BIP34Height = -1;
        consensus.BIP34Hash = uint256();
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1916; // 95% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nTargetTimespan / nTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

//      Deployment of BIP68, BIP112, and BIP113.
//      consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
//      consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 999999999999ULL; // never
//      consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 0; // out of time

        consensus.nProtocolV1RetargetingFixedTime = 1503468000;
        consensus.nProtocolV2Time = 1503468000;
        consensus.nProtocolV3Time = 1503468000;
        consensus.nLastPOWBlock = 10000;
        consensus.nStakeTimestampMask = 0xf; // 15   //AAM CHECK THIS
        consensus.nCoinbaseMaturity = 120;
        consensus.nStakeMinConfirmations = 120;
        consensus.nStakeMinAge = 8 * 60 * 60; // 8 hours

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xce;
        pchMessageStart[1] = 0xf1;
        pchMessageStart[2] = 0xdb;
        pchMessageStart[3] = 0xfa;
        vAlertPubKey = ParseHex("044a517b6e40a97753077912ae0b7e24c9c27ff4526cd1810dbb0e9fc95f653e4faade8fbe96b2bfd6a69ccc65a85c8ab51e6489cece39125f714bfb5fb6c6e896");
        nDefaultPort = 19534;
        nMaxTipAge = 24 * 60 * 60;
        nPruneAfterHeight = 100000;

        const char* pszTimestamp = "23 aug 2017 Floyd Mayweather v Conor McGregor: Chaos at media event in Las Vegas";
        CMutableTransaction txNew;
        txNew.nTime = 1503468000;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 0 << CScriptNum(42) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].SetEmpty();
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock.SetNull();
        genesis.nVersion = 1;
        genesis.nTime    = 1503468000;
        genesis.nBits    = 0x1e0fffff; //AAM CHECK THIS
        genesis.nNonce = 1294527;
        genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x00000a070895a3179065b7c8aa1ca794b2e5a06db5bec55b964ac495985085fd"));
        assert(genesis.hashMerkleRoot == uint256S("0x10b19e6c172f259d81cb2935e10033dd70e4eebad00d104a7807d1a09599c51e"));

        vSeeds.push_back(CDNSSeedData("seed.bitstarcoin.com", "seed.bitstarcoin.com"));
        vSeeds.push_back(CDNSSeedData("seed2.bitstarcoin.com", "seed2.bitstarcoin.com"));
        vSeeds.push_back(CDNSSeedData("seed3.bitstarcoin.com", "seed3.bitstarcoin.com"));
        vSeeds.push_back(CDNSSeedData("seed4.bitstarcoin.com", "seed4.bitstarcoin.com"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,25);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,8);
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1,153);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();
        cashaddrPrefix = "bitstarcoin";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = (CCheckpointData) {
                    boost::assign::map_list_of
                    ( 10000, uint256S("105f65275c8e6c14c1edac4d7bb6ab1da1dc07a09cbd450957f2d35118c1b2fc")),  // last pow block
                    1518010642, // * UNIX timestamp of last checkpoint block
                    10000,    // * total number of transactions between genesis and last checkpoint
                                //   (the tx=... number in the SetBestChain debug.log lines)
                    2880.0      // * estimated number of transactions per day after checkpoint
        };
    }
};
static CMainParams mainParams;

/**
 * Testnet
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nMaxReorganizationDepth = 50;
        consensus.nMajorityEnforceBlockUpgrade = 51;
        consensus.nMajorityRejectBlockOutdated = 75;
        consensus.nMajorityWindow = 100;
        consensus.powLimit = uint256S("0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.posLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.posLimitV2 = uint256S("000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nTargetTimespan = 16 * 60; // 16 mins
        consensus.nTargetSpacingV1 = 60;
        consensus.nTargetSpacing = 64;
        consensus.BIP34Height = -1;
        consensus.BIP34Hash = uint256();
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        consensus.nProtocolV1RetargetingFixedTime = 1395631999;
        consensus.nProtocolV2Time = 1407053625;
        consensus.nProtocolV3Time = 1444028400;
        consensus.nLastPOWBlock = 0x7fffffff;
        consensus.nStakeTimestampMask = 0xf; // 15
        consensus.nCoinbaseMaturity = 50;
        consensus.nStakeMinConfirmations = 50;
        consensus.nStakeMinAge = 1 * 60 * 60; // 1 hour

        pchMessageStart[0] = 0xce;
        pchMessageStart[1] = 0xf1;
        pchMessageStart[2] = 0xdb;
        pchMessageStart[3] = 0xfa;
        vAlertPubKey = ParseHex("049df4f51a6e93667687d26277555954eed8a2dc7f1a6fce2d0976aa394bceb1348e39ff53a9f79186695d9fc95ffb7244b2aef57573519554e8d023a8c2129a00");
        nDefaultPort = 29534;
        nMaxTipAge = 0x7fffffff;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1503468000, 233903, 0x1f00ffff, 1, 0);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x0000cdea654056f131dc28e7631ac9e6128d04ad41ac38f87f53cc3a5efcf500"));
        assert(genesis.hashMerkleRoot == uint256S("0x10b19e6c172f259d81cb2935e10033dd70e4eebad00d104a7807d1a09599c51e"));

        vFixedSeeds.clear();
        vSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();
        cashaddrPrefix = "blktest";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            ( 0, uint256S("0x0000cdea654056f131dc28e7631ac9e6128d04ad41ac38f87f53cc3a5efcf500")),
            0,
            0,
            0
        };

    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nMaxReorganizationDepth = 500;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow = 1000;
        consensus.powLimit = uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.posLimit = uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.posLimitV2 = uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nTargetTimespan = 16 * 60; // 16 mins
        consensus.nTargetSpacingV1 = 60;
        consensus.nTargetSpacing = 64;
        consensus.BIP34Height = -1; // BIP34 has not necessarily activated on regtest
        consensus.BIP34Hash = uint256();
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 1916; // 95% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nTargetTimespan / nTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
//        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
//        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 999999999999ULL; // never
//        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 0; // out of time

        consensus.nProtocolV1RetargetingFixedTime = 1400000000;
        consensus.nProtocolV2Time = 1410000000;
        consensus.nProtocolV3Time = 1420000000;
        consensus.nLastPOWBlock = 10000;
        consensus.nStakeTimestampMask = 0xf;

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0x70;
        pchMessageStart[1] = 0x35;
        pchMessageStart[2] = 0x22;
        pchMessageStart[3] = 0x06;
        vAlertPubKey = ParseHex("042508124261e3c969d9b4988349c41a329c6979e446facffc3227e16e5420c366e7d917e8ef80e70a27b90582272c93b6d0f16b0c728b970f73478167729cbbea");
        nDefaultPort = 39534;
        nMaxTipAge = 0x7fffffff;
        nPruneAfterHeight = 100000;

        /**
                 * Build the genesis block. Note that the output of its generation
                 * transaction cannot be spent since it did not originally exist in the
                 * database.
                 *
                 * CBlock(hash=000001faef25dec4fbcf906e6242621df2c183bf232f263d0ba5b101911e4563, ver=1, hashPrevBlock=0000000000000000000000000000000000000000000000000000000000000000, hashMerkleRoot=12630d16a97f24b287c8c2594dda5fb98c9e6c70fc61d44191931ea2aa08dc90, nTime=1393221600, nBits=1e0fffff, nNonce=164482, vtx=1, vchBlockSig=)
                 *   Coinbase(hash=12630d16a9, ver=1, nTime=1393221600, vin.size=1, vout.size=1, nLockTime=0)
                 *     CTxIn(COutPoint(0000000000, 4294967295), coinbase 00012a24323020466562203230313420426974636f696e2041544d7320636f6d6520746f20555341)
                 *     CTxOut(empty)
                 *   vMerkleTree: 12630d16a9
                 */
        const char* pszTimestamp = "20 Feb 2014 Bitcoin ATMs come to USA";
        CMutableTransaction txNew;
        txNew.nTime = 1393221600;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 0 << CScriptNum(42) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].SetEmpty();
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock.SetNull();
        genesis.nVersion = 1;
        genesis.nTime    = 1393221600;
        genesis.nBits    = 0x1e0fffff;
        genesis.nNonce = 164482;
        genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x000001faef25dec4fbcf906e6242621df2c183bf232f263d0ba5b101911e4563"));
        assert(genesis.hashMerkleRoot == uint256S("0x12630d16a97f24b287c8c2594dda5fb98c9e6c70fc61d44191931ea2aa08dc90"));

        vFixedSeeds.clear(); //! Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();  //! Regtest mode doesn't have any DNS seeds.

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,25);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,85);
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1,153);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();
        cashaddrPrefix = "blkreg";

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
			( 0, uint256S("0x000001faef25dec4fbcf906e6242621df2c183bf232f263d0ba5b101911e4563")),
            0,
            0,
            0
        };

    }
};
static CRegTestParams regTestParams;



static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
            return mainParams;
    else if (chain == CBaseChainParams::TESTNET)
            return testNetParams;
    else if (chain == CBaseChainParams::REGTEST)
            return regTestParams;
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

