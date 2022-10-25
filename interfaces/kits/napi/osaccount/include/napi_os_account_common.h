/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OS_ACCOUNT_INTERFACES_KITS_NAPI_OSACCOUNT_INCLUDE_NAPI_OS_ACCOUNT_COMMON_H
#define OS_ACCOUNT_INTERFACES_KITS_NAPI_OSACCOUNT_INCLUDE_NAPI_OS_ACCOUNT_COMMON_H

#include "account_info.h"
#include "napi_os_account.h"
#include "os_account_manager.h"
#include "ohos_account_kits.h"

namespace OHOS {
namespace AccountJsKit {
constexpr std::int32_t MAX_VALUE_LEN = 4096;
constexpr std::int32_t MAX_SUBSCRIBER_NAME_LEN = 1024;
constexpr const std::int32_t STR_MAX_SIZE = 256;
constexpr int PARAMZERO = 0;
constexpr int PARAMONE = 1;
constexpr int PARAMTWO = 2;
constexpr int PARAMTHREE = 3;
constexpr int RESULT_COUNT = 2;
constexpr std::int32_t ARGS_SIZE_ONE = 1;
constexpr std::int32_t ARGS_SIZE_TWO = 2;
constexpr std::int32_t ARGS_SIZE_THREE = 3;
constexpr std::int32_t ARGS_SIZE_FOUR = 4;

napi_value WrapVoidToJS(napi_env env);

bool ParseParaQueryOAByIdCB(napi_env env, napi_callback_info cbInfo, QueryOAByIdAsyncContext *queryOAByIdCB);

void QueryOAByIdExecuteCB(napi_env env, void *data);

void QueryOAByIdCallbackCompletedCB(napi_env env, napi_status status, void *data);

void GetOACBInfoToJs(napi_env env, OsAccountInfo &info, napi_value &result);

void MakeArrayToJs(napi_env env, const std::vector<std::string> &constraints, napi_value jsArray);

bool ParseParaRemoveOACB(napi_env env, napi_callback_info cbInfo, RemoveOAAsyncContext *removeOACB);

void RemoveOAExecuteCB(napi_env env, void *data);

void RemoveOACallbackCompletedCB(napi_env env, napi_status status, void *data);

bool ParseParaSetOAName(napi_env env, napi_callback_info cbInfo, SetOANameAsyncContext *setOANameCB);

void SetOANameExecuteCB(napi_env env, void *data);

void SetOANameCallbackCompletedCB(napi_env env, napi_status status, void *data);

bool ParseParaSetOAConstraints(napi_env env, napi_callback_info cbInfo, SetOAConsAsyncContext *setOAConsCB);

void SetOAConsExecuteCB(napi_env env, void *data);

void SetOAConsCallbackCompletedCB(napi_env env, napi_status status, void *data);

bool ParseParaActiveOA(napi_env env, napi_callback_info cbInfo, ActivateOAAsyncContext *activeOACB);

void ActivateOAExecuteCB(napi_env env, void *data);

void ActivateOACallbackCompletedCB(napi_env env, napi_status status, void *data);

bool ParseParaCreateOA(napi_env env, napi_callback_info cbInfo, CreateOAAsyncContext *createOACB);

bool ParseParaCreateOAForDomain(napi_env env, napi_callback_info cbInfo,
    CreateOAForDomainAsyncContext *createOAForDomainCB);

void CreateOAExecuteCB(napi_env env, void *data);

void CreateOAForDomainExecuteCB(napi_env env, void *data);

void CreateOACallbackCompletedCB(napi_env env, napi_status status, void *data);

void CreateOAForDomainCallbackCompletedCB(napi_env env, napi_status status, void *data);

bool ParseParaGetOACount(napi_env env, napi_callback_info cbInfo, GetOACountAsyncContext *getOACount);

void GetOACountExecuteCB(napi_env env, void *data);

void GetOACountCallbackCompletedCB(napi_env env, napi_status status, void *data);

bool ParseParaDbDeviceId(napi_env env, napi_callback_info cbInfo, DbDeviceIdAsyncContext *dbDeviceId);

void DbDeviceIdExecuteCB(napi_env env, void *data);

void DbDeviceIdCallbackCompletedCB(napi_env env, napi_status status, void *data);

bool ParseParaGetAllCons(napi_env env, napi_callback_info cbInfo, GetAllConsAsyncContext *getAllConsCB);

void GetAllConsExecuteCB(napi_env env, void *data);

void GetAllConsCallbackCompletedCB(napi_env env, napi_status status, void *data);

void GetAllAccountCons(napi_env env, const std::vector<std::string> &info, napi_value &result);

bool ParseParaProcessId(napi_env env, napi_callback_info cbInfo, GetIdAsyncContext *getIdCB);

void GetProcessIdExecuteCB(napi_env env, void *data);

void GetProcessIdCallbackCompletedCB(napi_env env, napi_status status, void *data);

bool ParseQueryAllCreateOA(napi_env env, napi_callback_info cbInfo, QueryCreateOAAsyncContext *queryAllOA);

bool ParseQueryActiveIds(napi_env env, napi_callback_info cbInfo, QueryActiveIdsAsyncContext *queryActiveIds);

void QueryCreateOAExecuteCB(napi_env env, void *data);

void QueryActiveIdsExecuteCB(napi_env env, void *data);

void QueryCreateOACallbackCompletedCB(napi_env env, napi_status status, void *data);

void QueryActiveIdsCallbackCompletedCB(napi_env env, napi_status status, void *data);

void QueryOAInfoForResult(napi_env env, const std::vector<OsAccountInfo> &info, napi_value &result);

bool ParseParaGetPhoto(napi_env env, napi_callback_info cbInfo, GetOAPhotoAsyncContext *getPhoto);

void GetOAPhotoExecuteCB(napi_env env, void *data);

void GetOAPhotoCallbackCompletedCB(napi_env env, napi_status status, void *data);

bool ParseParaCurrentOA(napi_env env, napi_callback_info cbInfo, CurrentOAAsyncContext *currentOA);

void QueryCurrentOAExecuteCB(napi_env env, void *data);

void QueryCurrentOACallbackCompletedCB(napi_env env, napi_status status, void *data);

bool ParseParaGetIdByUid(napi_env env, napi_callback_info cbInfo, GetIdByUidAsyncContext *idByUid);

bool ParseParaGetIdByDomain(napi_env env, napi_callback_info cbInfo, GetIdByDomainAsyncContext *idByDomain);

void GetIdByUidExecuteCB(napi_env env, void *data);

void GetBundleIdByUidExecuteCB(napi_env env, void *data);

void GetIdByDomainExecuteCB(napi_env env, void *data);

void GetIdByUidCallbackCompletedCB(napi_env env, napi_status status, void *data);

void GetBundleIdByUidCallbackCompletedCB(napi_env env, napi_status status, void *data);

void GetIdByDomainCallbackCompletedCB(napi_env env, napi_status status, void *data);

bool ParseParaSetPhoto(napi_env env, napi_callback_info cbInfo, SetOAPhotoAsyncContext *setPhoto);

void SetPhotoExecuteCB(napi_env env, void *data);

void SetPhotoCompletedCB(napi_env env, napi_status status, void *data);

bool ParseParaQueryMaxNum(napi_env env, napi_callback_info cbInfo, QueryMaxNumAsyncContext *maxNum);

void QueryMaxNumExecuteCB(napi_env env, void *data);

void QueryMaxNumCompletedCB(napi_env env, napi_status status, void *data);

bool ParseParaIsActived(napi_env env, napi_callback_info cbInfo, IsActivedAsyncContext *isActived);

void IsActivedExecuteCB(napi_env env, void *data);

void IsActivedCompletedCB(napi_env env, napi_status status, void *data);

bool ParseParaIsEnable(napi_env env, napi_callback_info cbInfo, IsConEnableAsyncContext *isEnable);

void IsEnableExecuteCB(napi_env env, void *data);

void IsEnableCompletedCB(napi_env env, napi_status status, void *data);

bool ParseParaGetType(napi_env env, napi_callback_info cbInfo, GetTypeAsyncContext *getType);

void GetTypeExecuteCB(napi_env env, void *data);

void GetTypeCompletedCB(napi_env env, napi_status status, void *data);

bool ParseParaIsMultiEn(napi_env env, napi_callback_info cbInfo, IsMultiEnAsyncContext *multiEn);

void IsMultiEnExecuteCB(napi_env env, void *data);

void IsMultiEnCompletedCB(napi_env env, napi_status status, void *data);

bool ParseParaIsVerified(napi_env env, napi_callback_info cbInfo, IsVerifiedAsyncContext *isVerified);

void IsVerifiedExecuteCB(napi_env env, void *data);

void IsVerifiedCompletedCB(napi_env env, napi_status status, void *data);

bool ParseParaSerialNumId(napi_env env, napi_callback_info cbInfo, GetSerialNumIdCBInfo *serialNumId);

void SerialNumIdExecuteCB(napi_env env, void *data);

void SerialNumIdCompletedCB(napi_env env, napi_status status, void *data);

bool ParseParaGetSerialNum(napi_env env, napi_callback_info cbInfo, GetSerialNumForOAInfo *getSerialNum);

void GetSerialNumExecuteCB(napi_env env, void *data);

void GetSerialNumCompletedCB(napi_env env, napi_status status, void *data);

bool ParseParaIsTestOA(napi_env env, napi_callback_info cbInfo, IsTestOAInfo *isTest);

bool ParseParaIsMainOA(napi_env env, napi_callback_info cbInfo, IsMainOAInfo *isMain);

bool ParseParaToSubscriber(const napi_env &env, napi_callback_info cbInfo, SubscribeCBInfo *asyncContext,
                           napi_value *thisVar);

void SubscribeExecuteCB(napi_env env, void *data);

void SubscribeCompletedCB(napi_env env, napi_status status, void *data);

bool ParseParaToUnsubscriber(
    const napi_env &env, napi_callback_info cbInfo, UnsubscribeCBInfo *asyncContext, napi_value *thisVar);

bool ParseQueryOAConstraintSrcTypes(napi_env env, napi_callback_info cbInfo,
    QueryOAConstraintSrcTypeContext *queryConstraintsSource);

void QueryOAContSrcTypeExecuteCB(napi_env env, void *data);

void QueryOAContSrcTypeCallbackCompletedCB(napi_env env, napi_status status, void *data);

void QueryOAContSrcTypeForResult(napi_env env, const std::vector<ConstraintSourceTypeInfo> &infos, napi_value &result);
}  // namespace AccountJsKit
}  // namespace OHOS

#endif  // OS_ACCOUNT_INTERFACES_KITS_NAPI_OSACCOUNT_INCLUDE_NAPI_OS_ACCOUNT_COMMON_H
