// Copyright (c) 2014-2017 Coin Sciences Ltd
// MultiChain code distributed under the GPLv3 license, see COPYING file.

// Copyright (c) 2017 Hdac Technology AG
// Hdac code distributed under the GPLv3 license, see COPYING file.
/*============================================================================================
   History
   
   2018/01/00	Rename file 
   2018/02/00   code optimization
============================================================================================*/

#ifndef _HDACSCRIPT_H_
#define	_HDACSCRIPT_H_

#include "utils/declare.h"

#define MC_SCR_TYPE_SCRIPTPUBKEY                      0
#define MC_SCR_TYPE_SCRIPTSIG                         1
#define MC_SCR_TYPE_SCRIPTSIGRAW                      2

#define MC_SCR_ASSET_SCRIPT_TYPE_TRANSFER              0x00000001
#define MC_SCR_ASSET_SCRIPT_TYPE_FOLLOWON              0x00000002


#if 1//ithong_hmpl
typedef enum{
    HMPL_SCRIPT_MODE_USER = 1,
    HMPL_SCRIPT_MODE_ADMIN_S  = 65533,// 0xFFFD,
    HMPL_SCRIPT_MODE_ADMIN_P  = 65534,// 0xFFFE,
}HmplScriptModeEnumType;

#define HMPLSCRIPT_SVC_HIGH_ADMIN 0
#define HMPLSCRIPT_SVC_LOW_ADMIN_S 0
#define HMPLSCRIPT_SVC_LOW_ADMIN_P 1

typedef struct 
{    
    uint16_t version;
    uint16_t mode;
    uint32_t svc_h;
    uint32_t svc_l;
    uint16_t size;
}hmplscript_head;
#endif

typedef struct mc_Script
{    
    int m_Size;
    int m_NumElements;
    int m_CurrentElement;
    unsigned char* m_lpData;
    int *m_lpCoord;
    int m_AllocElements;
    int m_AllocSize;
    int m_ScriptType;
    
    mc_Script()
    {
        Zero();
    }

    ~mc_Script()
    {
        Destroy();
    }
    
    int Zero();
    int Destroy();    
    int Resize(size_t bytes,int elements);
    
    int SetScript(const unsigned char* src,const size_t bytes,int type);
    int IsOpReturnScript();
    int IsDirtyOpReturnScript();
    int Clear();
    
    int GetNumElements();
    int AddElement();
    int SetSpecialParamValue(unsigned char param,const unsigned char* param_value,const size_t param_value_size);
    int SetParamValue(const char *param_name,const size_t param_name_size,const unsigned char* param_value,const size_t param_value_size);
    size_t GetParamValue(const unsigned char *ptr,size_t total,size_t offset,size_t* param_value_start,size_t *bytes);
    int SetData(const unsigned char* src,const size_t bytes);
    const unsigned char* GetData(int element,size_t *bytes);
    
    int GetElement();
    int SetElement(int element);
    
    int GetEntity(unsigned char *short_txid);
    int SetEntity(const unsigned char *short_txid);

    int GetNewEntityType(uint32_t *type);
    int SetNewEntityType(const uint32_t type);

    int GetApproval(uint32_t *approval,uint32_t *timestamp);
    int SetApproval( uint32_t approval,uint32_t timestamp);
    
    int GetNewEntityType(uint32_t *type,int *update,unsigned char* script,int *script_size);
    int SetNewEntityType(const uint32_t type,const int update,const unsigned char* script,int script_size);

    int GetItemKey(unsigned char *key,int *key_size);
    int SetItemKey(const unsigned char* key,int key_size);
    
    int GetPermission(uint32_t *type,uint32_t *from,uint32_t *to,uint32_t *timestamp);
    int SetPermission(uint32_t type,uint32_t from,uint32_t to,uint32_t timestamp);
    
    int GetBlockSignature(unsigned char* sig,int *sig_size,uint32_t *hash_type,unsigned char* key,int *key_size);
    int SetBlockSignature(const unsigned char* sig,int sig_size,uint32_t hash_type,const unsigned char* key,int key_size);
        
    int GetAssetGenesis(int64_t *quantity);
    int SetAssetGenesis(int64_t quantity);
    
    int GetAssetDetails(char* name,int* multiple,unsigned char* script,int *script_size);
    int SetAssetDetails(const char*name,int multiple,const unsigned char* script,int script_size);
    
    int GetGeneralDetails(unsigned char* script,int *script_size);
    int SetGeneralDetails(const unsigned char* script,int script_size);
    
    int GetAssetQuantities(mc_Buffer *amounts,uint32_t script_type);
    int SetAssetQuantities(mc_Buffer *amounts,uint32_t script_type);

    int GetFullRef(unsigned char *ref,uint32_t *script_type);
    
    int GetCachedScript(int offset, int *next_offset, int* vin, unsigned char** script, int *script_size);
    int SetCachedScript(int offset, int *next_offset, int vin, unsigned char* script, int script_size);
#if 0//ithong_hmpl
    int  SetHmplRaw(uint16_t mode, uint32_t svc_h, uint32_t svc_l, uint16_t size_info, unsigned char *info);
    int  SetHmplRaw(hmplscript_head *head, unsigned char *info);
    int  GethmplRaw(uint16_t *mode, uint32_t *svc_h, uint32_t *svc_l, uint16_t *size_info, unsigned char *info);
    int  Gethmplinfo(hmplscript_head *head, unsigned char *info);
    //int  GethmplMsg(HmplMsgType *msg);
    int  ProcessHmpl(unsigned char *hmpl);
    bool IsHmpl(void);
#endif
#if 1//ithong_hmpl
int  SetHmplRaw(uint16_t mode, uint32_t svc_h, uint32_t svc_l, uint16_t size_info, unsigned char *info);
int  GethmplRaw(uint16_t *mode, uint32_t *svc_h, uint32_t *svc_l, uint16_t *size_info, unsigned char *info);
int  Gethmplinfo(hmplscript_head *head, unsigned char *info);
bool IsHmpl(void);
#endif
} mc_Script;


#endif	/* _HDACSCRIPT_H_ */

