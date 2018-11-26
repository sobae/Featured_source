#include "cust/custhdac.h"

#include "protocol/hdac/hmpl.h"

#include "structs/amount.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "structs/hash.h"
#include "core/main.h"
#include "net/net.h"
#include "structs/base58.h"
#include "utils/timedata.h"
#include "utils/util.h"
#include "utils/utilmoneystr.h"
#include "utils/utilparse.h"
#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#endif

//#include "hdac/hdac.h"

#include <boost/thread.hpp>
#include <boost/tuple/tuple.hpp>

using namespace std;

#if 1//ithong_hmpl
CCriticalSection cs_HMPLTransaction;	
std::map<uint256, HmplMsgType> mapHMPLTransaction;
std::map<uint256, HmplMsgType> mapHMPLProcMsg;

//mapOrphanTransactions.count(hash)
//mapOrphanTransactionsByPrev[txin.prevout.hash].insert(hash);

//map<uint256, COrphanTx>::iterator it = mapOrphanTransactions.find(hash);
//mapOrphanTransactions.erase(it);
	
#endif

#if 1//ithong_hmpl

void GetHmplList(std::map<uint256, HmplMsgType>& mHmpl)
{
    if(fDebug>1) LogPrint("hmpl"," GetHmplList:mapHMPLProcMsg.size=%d \n", mapHMPLProcMsg.size());  
	
    for (std::map<uint256, HmplMsgType> ::const_iterator mi = mapHMPLProcMsg.begin();mi != mapHMPLProcMsg.end();++mi)
    {
        mHmpl.insert(make_pair(mi->first, mi->second));
    }
}


bool CheckFreeHMPL(CTransaction txNew, const CCoinsViewCache& mapInputs)
{
    CAmount hmpl_outValue = 0;
    uint16_t hmpl_mode = 0;
    uint32_t hmpl_perm = 0, hmpl_perm_t = 0;
    bool hmpl_included = false;
    unsigned int m;
    vector<CTxDestination> addressRetsVin;
    bool bStatus = true;

    if(txNew.vin.size()!=1) return false;

    // check v_in
    for (m = 0;(( m < txNew.vin.size()) && bStatus); m++) 
    {
        const COutPoint &prevout = txNew.vin[m].prevout;
        const CCoins *coins = mapInputs.AccessCoins(prevout.hash);
        const CScript& script1 = coins->vout[prevout.n].scriptPubKey;        
        CScript::const_iterator pc1 = script1.begin();
        
        txnouttype typeRet;
        int nRequiredRet;		
			
        if(ExtractDestinations(script1,typeRet,addressRetsVin,nRequiredRet))
        {
            //LogPrintf(" CheckHMPL_AMP: typeRet=%d, nRequiredRet=%d \n", typeRet, nRequiredRet);   
			
            if ((typeRet != TX_NULL_DATA) && (typeRet != TX_MULTISIG))
            {
                continue;
            }
            else
            {
                bStatus = false;
            }
        }
        else
        {
            bStatus = false;
        }
    }

    if(!bStatus) return false;

    hmpl_perm_t = 0;
    for (m = 0;(( m < addressRetsVin.size()) && bStatus); m++) 
    {  
        CKeyID *lpKeyID=boost::get<CKeyID> (&addressRetsVin[m]);
        if(lpKeyID != NULL)
        { 
            hmpl_perm_t |= mc_gState->m_Permissions->CanAdmin(NULL,(unsigned char*)lpKeyID);
        }
        else
        {
            bStatus = false;
        }
    }

    if(!bStatus) return false;	

    hmpl_perm = hmpl_perm_t;
    hmpl_perm_t = 0;

    //LogPrintf(" CheckHMPL_AMP: hmpl_perm=%08x \n", hmpl_perm);

    for (m = 0; m < txNew.vout.size();m++)
    {
        const CScript& script_temp = txNew.vout[m].scriptPubKey;
        CTxDestination addressRet;        
        if(ExtractDestinationScriptValid(script_temp, addressRet))
        {
            CKeyID *lpKeyID=boost::get<CKeyID> (&addressRet);
            if(lpKeyID != NULL)
            {
                bool nVinDuplicated = false;
                unsigned int j;
                for (j = 0; j < addressRetsVin.size();j++)
                {
                    CKeyID *lpaddressRetsVin=boost::get<CKeyID> (&addressRetsVin[j]);
                    unsigned char*paddressRetsVin = (unsigned char*)lpaddressRetsVin;
                    if(memcmp(paddressRetsVin,(unsigned char*)(lpKeyID),20)==0)
                    {
                        nVinDuplicated = true;
                        continue;
                    }
                }

                if(!nVinDuplicated)
                {  
                    hmpl_perm_t |= mc_gState->m_Permissions->CanAdmin(NULL,(unsigned char*)(lpKeyID));
                    //LogPrintf(" CheckFreeHMPL: hmpl_perm_t=%08x, nValueOut=%d \n", hmpl_perm_t, txNew.vout[m].nValue);  
                    hmpl_outValue += txNew.vout[m].nValue;

                    CScript::const_iterator pc1 = script_temp.begin();
                    mc_Script m_TmpScript;
                    m_TmpScript.Clear();
                    m_TmpScript.SetScript((unsigned char*)(&pc1[0]),(size_t)(script_temp.end()-pc1),MC_SCR_TYPE_SCRIPTPUBKEY);

                    if(m_TmpScript.GetNumElements()==1)
                    {
                        m_TmpScript.SetElement(0);  
                        #if 1//block for build
                        if((m_TmpScript.IsHmpl()) && (m_TmpScript.GethmplRaw(&hmpl_mode, NULL, NULL, NULL, NULL)==0))
                        {
                            hmpl_included = true;
                        }
                        #endif
                    }
                }
            }
            else                            
            {
                return false;
            }
        }
    }

    hmpl_perm |= hmpl_perm_t;
    hmpl_perm &=MC_PTP_ADMIN;

    bStatus = false;

    if( (hmpl_included) && (hmpl_outValue==0))
    {
        if(fDebug>1) LogPrint("hmpl"," CheckFreeHMPL: hmpl_perm_t=%08x, hmpl_mode=%d \n", hmpl_perm,  hmpl_mode);  
		
        switch(hmpl_mode)
        {
        case HMPL_SCRIPT_MODE_ADMIN_S:
            if(hmpl_perm == MC_PTP_ADMIN) bStatus = true;
            break;
        case HMPL_SCRIPT_MODE_ADMIN_P:
            if(hmpl_perm == MC_PTP_ADMIN) bStatus = true;
            break;
        default:
            break;
        }
    }

    //if(bStatus) LogPrintf(" CheckHMPL: admin service \n");  
	
    return bStatus;
}
#endif


#if 1
//ithong_hmpl
bool CheckFreeHMPLtransaction(CMutableTransaction txNew, std::set<CTxDestination>* usedAddresses)
{
    CAmount nTotalOutValue;
    uint16_t hmpl_mode = 0;
    uint32_t hmpl_perm = 0;
    bool hmpl_included = false;
    unsigned int m;
    bool bStatus = false;

    const unsigned char* used_aptr;
    int check_count = 0;

    if(txNew.vin.size()!=1) return false;

    BOOST_FOREACH(const CTxDestination& address, *usedAddresses)
    {        
        used_aptr=GetAddressIDPtr(address);
        check_count ++;
    }

    if(check_count!=1) return false;

    if(used_aptr)
    {
        uint32_t perm = mc_gState->m_Permissions->CanAdmin(NULL,used_aptr);
        hmpl_perm |= perm;
        //LogPrintf(" CheckHMPL: perm=%08x, perm2=%08x \n", perm, hmpl_perm);
    }
    else
    {
        return false;
    }

    for (unsigned int m = 0; m < txNew.vout.size();m++)
    {
        const CScript& script_temp = txNew.vout[m].scriptPubKey;
        CTxDestination addressRet;        
        if(ExtractDestinationScriptValid(script_temp, addressRet))
        {
            CKeyID *lpKeyID=boost::get<CKeyID> (&addressRet);
            if(lpKeyID != NULL)
            {
                if(memcmp(used_aptr,(unsigned char*)(lpKeyID),20))
                {
                    uint32_t perm = mc_gState->m_Permissions->CanAdmin(NULL,(unsigned char*)(lpKeyID));
                    hmpl_perm |= perm;
                    //LogPrintf(" CheckHMPL: perm=%08x, perm2=%08x, nValue=%d \n", perm, hmpl_perm, txNew.vout[m].nValue);  
                    nTotalOutValue += txNew.vout[m].nValue;

                    CScript::const_iterator pc1 = script_temp.begin();
                    mc_Script m_TmpScript;
                    int hmpl_result = 0;
                    m_TmpScript.Clear();
                    m_TmpScript.SetScript((unsigned char*)(&pc1[0]),(size_t)(script_temp.end()-pc1),MC_SCR_TYPE_SCRIPTPUBKEY);

                    if(m_TmpScript.GetNumElements()==1)
                    {
                        m_TmpScript.SetElement(0);
						#if 1//block for build
                        if((m_TmpScript.IsHmpl()) && (m_TmpScript.GethmplRaw(&hmpl_mode, NULL, NULL, NULL, NULL)==0))
                        {
                            hmpl_included = true;
                        }
						#endif
                    }
                }
            }
            else                            
            {
                return false;
            }
        }
    }

    hmpl_perm &= MC_PTP_ADMIN;

    if( (hmpl_included) && (nTotalOutValue == 0))
    {
	if(fDebug>1) LogPrint("hmpl"," CheckHMPL: hmpl_perm=%08x, hmpl_mode=%d \n", hmpl_perm,  hmpl_mode);
	
        switch(hmpl_mode)
        {
        case HMPL_SCRIPT_MODE_ADMIN_S:
            if(hmpl_perm == MC_PTP_ADMIN) bStatus = true;
            break;
        case HMPL_SCRIPT_MODE_ADMIN_P:
            if(hmpl_perm == MC_PTP_ADMIN) bStatus = true;
            break;
        default:
            break;
        }
    }

    //if(bStatus) LogPrintf(" CheckHMPL: admin service \n");  

    return bStatus;    
}
#endif

void addHmplMsg(uint256 hash, hmplscript_head *head, unsigned char* body)
{
    HmplMsgType msg;

    if(fDebug>1) LogPrint("hmpl","addHmplMsg : mapHMPLTransaction.size=%d, input=%s\n", mapHMPLTransaction.size(), hash.ToString());

    if(head)
    {
        msg.head = *head;
        if((msg.head.size>0) && (msg.head.size<=HDAC_HMPL_BUFF_MAX) && (body!=NULL))
        {
            for(int m=0;m<msg.head.size;m++) msg.dataData.push_back(body[m]);
        }
        
        //LogPrintf("addHmplMsg : mode=%d, svc_h=%d, svc_l=%d, size=%d\n", head->mode, head->svc_h, head->svc_l, head->size);
        
        if(mapHMPLTransaction.size() && mapHMPLTransaction.count(hash)) 
        {
            //LogPrintf("addHmplMsg :  duplicated !! . skip !!\n", mapHMPLTransaction.size());
            return;
        }
        mapHMPLTransaction.insert(make_pair(hash, msg));
    }
}

#if 0								
void addHmplMsg(uint256 hash, HmplMsgType *msg)
{
    if(msg==NULL) return;

    LogPrintf("addHmplMsg : mode=%d, svc_h=%d, svc_l=%d, size=%d\n", msg->head.mode, msg->head.svc_h, msg->head.svc_l, msg->head.size);

    if(mapHMPLTransaction.count(hash)) return;

    mapHMPLTransaction.insert(pair<uint256, HmplMsgType>(hash, *msg));
}
#endif

void ProcessHMPL()
{
    LOCK(cs_HMPLTransaction);
    std::map<uint256, HmplMsgType> temp_mapHMPLTransaction = mapHMPLTransaction;
    mapHMPLTransaction.clear();
    
    for (std::map<uint256, HmplMsgType> ::const_iterator mi = temp_mapHMPLTransaction.begin();mi != temp_mapHMPLTransaction.end();++mi)
    {
        const uint256 hash = mi->first;
        const HmplMsgType hmplMsg = mi->second;
        if(fDebug>1) LogPrint("hmpl","ProcessHMPL : hash=%s, size=%d, mode=%d\n", hash.ToString(), hmplMsg.head.size, hmplMsg.head.mode);
        mapHMPLProcMsg.insert(make_pair(hash, hmplMsg));
    }
}

#if 0
typedef struct 
{    
    uint16_t version; >> process type
    uint16_t mode;
    uint32_t svc_h;
    uint32_t svc_l;
    uint16_t size;
}hmplscript_head;

HMPL_SCRIPT_MODE_ADMIN_S  = 65533,// 0xFFFD,
HMPL_SCRIPT_MODE_ADMIN_P  = 65534,// 0xFFFE,

HMPL_SCRIPT_MODE_ADMIN_P : version

example
vote 
	mode : HMPL_SCRIPT_MODE_ADMIN_S

svc_h : 1 >> vote
svc_l : x >> main vote code

data : 
sub vote code
start time
end time
valid
receiver ?
info ? refer to related link.


request type
response type : need for reference
broadcast info?

data type
single
linked




#endif

void static HdacHmpl()//(CWallet *pwallet)
{
    if(fDebug>1) LogPrint("hmpl","[HdacHmpl] started\n");
    SetThreadPriority(THREAD_PRIORITY_LOWEST);
    RenameThread("hdac-hmpl");

    try {
        
        bool bStatusBreak = false;
        bool bGoSleep = false;
        int hmpl_count = 0;

        while (!bStatusBreak) {            
            
            if(mc_gState->m_Permissions->IsSetupPeriod())
            {
                bGoSleep=true;
            }
		else
		{
                hmpl_count = mapHMPLTransaction.size();
				//LogPrintf("HdacHmpl: hmpl_count=%d\n",hmpl_count);	// HDAC
                if(hmpl_count) ProcessHMPL();
                bGoSleep=true;
		}
            
            if(bGoSleep)            
            {
                __US_Sleep(1000);
                boost::this_thread::interruption_point();                                    
            } 
        }
    }
    catch (boost::thread_interrupted)
    {
        //LogPrintf("HdacHmpl terminated\n");	// HDAC
        throw;
    }
}

void ProcHMPL(bool bStatus)
{
    static boost::thread_group* hmplThreads = NULL;

    if(fDebug>1) LogPrint("hmpl","ThreadHMPL : bStatus=%d [%s]   \n",bStatus, (hmplThreads==NULL)?"null":"active");

    if (hmplThreads != NULL)
    {
        hmplThreads->interrupt_all();
        hmplThreads->join_all();
        
        delete hmplThreads;
        hmplThreads = NULL;
    }

    if (!bStatus)
        return;

    hmplThreads = new boost::thread_group();
    hmplThreads->create_thread(&HdacHmpl);        
}


