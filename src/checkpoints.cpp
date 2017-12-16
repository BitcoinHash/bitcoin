// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "checkpoints.h"

#include "main.h"
#include "uint256.h"

#include <stdint.h>

#include <boost/assign/list_of.hpp> // for 'map_list_of()'
#include <boost/foreach.hpp>

namespace Checkpoints
{
    typedef std::map<int, uint256> MapCheckpoints;

    // How many times we expect transactions after the last checkpoint to
    // be slower. This number is a compromise, as it can't be accurate for
    // every system. When reindexing from a fast disk with a slow CPU, it
    // can be up to 20, while when downloading from a slow network with a
    // fast multicore CPU, it won't be much higher than 1.
    static const double SIGCHECK_VERIFICATION_FACTOR = 5.0;

    struct CCheckpointData {
        const MapCheckpoints *mapCheckpoints;
        int64_t nTimeLastCheckpoint;
        int64_t nTransactionsLastCheckpoint;
        double fTransactionsPerDay;
    };

    bool fEnabled = true;

    // What makes a good checkpoint block?
    // + Is surrounded by blocks with reasonable timestamps
    //   (no blocks before with a timestamp after, none after with
    //    timestamp before)
    // + Contains no strange transactions
    static MapCheckpoints mapCheckpoints =
        boost::assign::map_list_of
            (      0, uint256("0x00000f639db5734b2b861ef8dbccc33aebd7de44d13de000a12d093bcc866c64"))
            (   6143, uint256("0x0000000026fb51f5bc9943ed69d9ff7697ecf7fed419d88b417655f93a487ce1"))
            (  12797, uint256("0x000000002c29644e179baa188fa6b9b9454721f1f21f2b9f31eebe9acc1a31db"))
            (  30092, uint256("0x0000000098a23e1c503f71a6d61c333c5abaabb4c5fa1b474012e004db4bfbbe"))
            (  80998, uint256("0x000000010ebcfe9a00a99f2b61104f4a141555a707f1c007aba8a978f6030cfb"))
            ( 144759, uint256("0x000000047e7b7bfd63b4f019a0a24c8d65b10afa6eb80721e10fa7c49ce6fb6e"))
            ( 189046, uint256("0x00000000bd507c435b46ee8a13b25b85ec38fdb0eb5b00faeaa0611cd6a483d3"))
            ( 277316, uint256("0x00000016a20503fe496e79d34fb85c33f633059315c046ffa1b4826d08a1e856"))
            ( 483849, uint256("0x000001eb7f8124282ab62296e63d3145ff6c84cf18afae4d4b8e02cd3182b6a8"))
            (1066428, uint256("0x000000012dc5256d977b50270d1ca5642726308dcf26b6c219985edb8f2ab8f6"))
        ;
    static const CCheckpointData data = {
        &mapCheckpoints,
        1490629503, // * UNIX timestamp of last checkpoint block
        1179921,    // * total number of transactions between genesis and last checkpoint
                    //   (the tx=... number in the SetBestChain debug.log lines)
        960         // * estimated number of transactions per day after checkpoint
    };

    static MapCheckpoints mapCheckpointsTestnet =
        boost::assign::map_list_of
        ( 546, uint256("000000002a936ca763904c3c35fce2f3556c559c0214345d31b1bcebf76acb70"))
        ;
    static const CCheckpointData dataTestnet = {
        &mapCheckpointsTestnet,
        1338180505,
        16341,
        300
    };

    static MapCheckpoints mapCheckpointsRegtest =
        boost::assign::map_list_of
        ( 0, uint256("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"))
        ;
    static const CCheckpointData dataRegtest = {
        &mapCheckpointsRegtest,
        0,
        0,
        0
    };

    const CCheckpointData &Checkpoints() {
        if (Params().NetworkID() == CChainParams::TESTNET)
            return dataTestnet;
        else if (Params().NetworkID() == CChainParams::MAIN)
            return data;
        else
            return dataRegtest;
    }

    bool CheckBlock(int nHeight, const uint256& hash)
    {
        if (!fEnabled)
            return true;

        const MapCheckpoints& checkpoints = *Checkpoints().mapCheckpoints;

        MapCheckpoints::const_iterator i = checkpoints.find(nHeight);
        if (i == checkpoints.end()) return true;
        return hash == i->second;
    }

    // Guess how far we are in the verification process at the given block index
    double GuessVerificationProgress(CBlockIndex *pindex, bool fSigchecks) {
        if (pindex==NULL)
            return 0.0;

        int64_t nNow = time(NULL);

        double fSigcheckVerificationFactor = fSigchecks ? SIGCHECK_VERIFICATION_FACTOR : 1.0;
        double fWorkBefore = 0.0; // Amount of work done before pindex
        double fWorkAfter = 0.0;  // Amount of work left after pindex (estimated)
        // Work is defined as: 1.0 per transaction before the last checkpoint, and
        // fSigcheckVerificationFactor per transaction after.

        const CCheckpointData &data = Checkpoints();

        if (pindex->nChainTx <= data.nTransactionsLastCheckpoint) {
            double nCheapBefore = pindex->nChainTx;
            double nCheapAfter = data.nTransactionsLastCheckpoint - pindex->nChainTx;
            double nExpensiveAfter = (nNow - data.nTimeLastCheckpoint)/86400.0*data.fTransactionsPerDay;
            fWorkBefore = nCheapBefore;
            fWorkAfter = nCheapAfter + nExpensiveAfter*fSigcheckVerificationFactor;
        } else {
            double nCheapBefore = data.nTransactionsLastCheckpoint;
            double nExpensiveBefore = pindex->nChainTx - data.nTransactionsLastCheckpoint;
            double nExpensiveAfter = (nNow - pindex->nTime)/86400.0*data.fTransactionsPerDay;
            fWorkBefore = nCheapBefore + nExpensiveBefore*fSigcheckVerificationFactor;
            fWorkAfter = nExpensiveAfter*fSigcheckVerificationFactor;
        }

        return fWorkBefore / (fWorkBefore + fWorkAfter);
    }

    int GetTotalBlocksEstimate()
    {
        if (!fEnabled)
            return 0;

        const MapCheckpoints& checkpoints = *Checkpoints().mapCheckpoints;

        return checkpoints.rbegin()->first;
    }

    CBlockIndex* GetLastCheckpoint(const std::map<uint256, CBlockIndex*>& mapBlockIndex)
    {
        if (!fEnabled)
            return NULL;

        const MapCheckpoints& checkpoints = *Checkpoints().mapCheckpoints;

        BOOST_REVERSE_FOREACH(const MapCheckpoints::value_type& i, checkpoints)
        {
            const uint256& hash = i.second;
            std::map<uint256, CBlockIndex*>::const_iterator t = mapBlockIndex.find(hash);
            if (t != mapBlockIndex.end())
                return t->second;
        }
        return NULL;
    }
}
