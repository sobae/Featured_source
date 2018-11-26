#ifndef HDAC_HMPL_H
#define HDAC_HMPL_H

#include <stdint.h>

#include <script/standard.h>
#include <set>
#include "storage/coins.h"
//#include "utils/sync.h"

class CBlock;
class CBlockHeader;
class CBlockIndex;
class CReserveKey;
class CScript;
class CWallet;

struct CBlockTemplate;

#if 1//ithong_hmpl
typedef struct{
    hmplscript_head head;
    std::vector<unsigned char> dataData;
}HmplMsgType;

typedef struct{
    uint256 hash;
    HmplMsgType msg;
}HmplTransaction;

#define HDAC_HMPL_BUFF_MAX 512


extern std::map<uint256, HmplMsgType> mapHMPLTransaction;
//extern std::map<uint256, HmplMsgType> mapHMPLProcMsg;
#endif

extern void GetHmplList(std::map<uint256, HmplMsgType>& mHmpl);
extern bool CheckFreeHMPL(CTransaction txNew, const CCoinsViewCache& mapInputs);
extern bool CheckFreeHMPLtransaction(CMutableTransaction txNew, std::set<CTxDestination>* usedAddresses);
extern void addHmplMsg(uint256 hash, hmplscript_head *head, unsigned char* body);
#if 0
void addHmplMsg(uint256 hash, HmplMsgType *msg);
#endif
void ProcessHMPL();
void ProcHMPL(bool bStatus);

#endif // HDAC_HMPL_H

