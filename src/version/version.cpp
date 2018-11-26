// Copyright (c) 2014-2017 Coin Sciences Ltd
// MultiChain code distributed under the GPLv3 license, see COPYING file.

// Copyright (c) 2017 Hdac Technology AG
// Hdac code distributed under the GPLv3 license, see COPYING file.
/*============================================================================================
   History
   
   2018/02/00   added HDAC version description
============================================================================================*/

#include "hdac/hdac.h"
#include "cust/custhdac.h"

#include "version/version.h"
#include "version/hdacversion.h"

const char* mc_State::GetVersion()
{
  #ifdef HDAC_VERSION_DEFINITION

    return HDAC_BUILD_DESC;
    
  #else
    return MULTICHAIN_BUILD_DESC;
  #endif
}

const char* mc_State::GetFullVersion()
{
  #ifdef HDAC_VERSION_DEFINITION

    return HDAC_FULL_VERSION;
    
  #else
    return MULTICHAIN_FULL_VERSION;
  #endif
}

int mc_State::GetNumericVersion()
{
  #ifdef HDAC_VERSION_DEFINITION
	
		return HDAC_BUILD_DESC_NUMERIC;
  #else
		return MULTICHAIN_BUILD_DESC_NUMERIC;
  #endif
}

int mc_State::GetWalletDBVersion()
{
    if(mc_gState->m_WalletMode & MC_WMD_ADDRESS_TXS)
    {
        if(mc_gState->m_WalletMode & MC_WMD_MAP_TXS)
        {
            return -1;                
        }
        else
        {
            return 2;                
        }
    }
    
    return 1;
}

int mc_State::GetProtocolVersion()
{
  #ifdef HDAC_VERSION_DEFINITION

    return HDAC_PROTOCOL_VERSION;
    
  #else
    return MULTICHAIN_PROTOCOL_VERSION;
  #endif
}

#ifdef FEATURE_HPAY_UPDATE_PARAMS_HASH
const int mc_State::GetRevision()
{
  return HDAC_BUILD_REVISION;
}

const bool mc_State::PrevParamsHash(unsigned char* hash)
{  
  if(!strcmp((char*)PARAMS_HASH_0_56_0_TESTNET, (char*)hash) || 
     !strcmp((char*)PARAMS_HASH_0_56_0_MAINNET, (char*)hash))
  {
    return true;
  }

  return false;
}
#endif/* FEATURE_HPAY_UPDATE_PARAMS_HASH */

