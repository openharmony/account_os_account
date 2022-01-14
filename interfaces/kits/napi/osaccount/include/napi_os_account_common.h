/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef NAPI_OS_ACCOUNT_COMMON_H
#define NAPI_OS_ACCOUNT_COMMON_H

#include "account_info.h"
#include "napi_os_account.h"
#include "os_account_manager.h"
#include "ohos_account_kits.h"

namespace OHOS {
namespace AccountJsKit {
#define PARAM0 0
#define PARAM1 1
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

int GetIntProperty(napi_env env, napi_value obj);

int64_t GetLongIntProperty(napi_env env, napi_value obj);

napi_value GetErrorCodeValue(napi_env env, int errCode);

std::string GetNamedProperty(napi_env env, napi_value obj);

napi_value ParseParaQueryOAByIdCB(napi_env env, napi_callback_info cbInfo, QueryOAByIdAsyncContext *queryOAByIdCB);

void QueryOAByIdExecuteCB(napi_env env, void *data);

void QueryOAByIdCallbackCompletedCB(napi_env env, napi_status status, void *data);

void GetOACBInfoToJs(napi_env env, OsAccountInfo &info, napi_value result);

void MakeArrayToJs(napi_env env, const std::vector<std::string> &constraints, napi_value jsArray);

void CBOrPromiseToQueryOAById(
    napi_env env, const QueryOAByIdAsyncContext *queryOAByIdCB, napi_value err, napi_value data);

napi_value ParseParaRemoveOACB(napi_env env, napi_callback_info cbInfo, RemoveOAAsyncContext *removeOACB);

void RemoveOAExecuteCB(napi_env env, void *data);

void RemoveOACallbackCompletedCB(napi_env env, napi_status status, void *data);

void CBOrPromiseToRemoveOA(napi_env env, const RemoveOAAsyncContext *removeOACB, napi_value err, napi_value data);

napi_value ParseParaSetOAName(napi_env env, napi_callback_info cbInfo, SetOANameAsyncContext *setOANameCB);

void SetOANameExecuteCB(napi_env env, void *data);

void SetOANameCallbackCompletedCB(napi_env env, napi_status status, void *data);

void CBOrPromiseToSetOAName(napi_env env, const SetOANameAsyncContext *setOANameCB, napi_value err, napi_value data);

napi_value ParseParaSetOAConstraints(napi_env env, napi_callback_info cbInfo, SetOAConsAsyncContext *setOAConsCB);

void SetOAConsExecuteCB(napi_env env, void *data);

void SetOAConsCallbackCompletedCB(napi_env env, napi_status status, void *data);

void CBOrPromiseToSetOACons(napi_env env, const SetOAConsAsyncContext *setOAConsCB, napi_value err, napi_value data);

napi_value ParseParaActiveOA(napi_env env, napi_callback_info cbInfo, ActivateOAAsyncContext *activeOACB);

void ActivateOAExecuteCB(napi_env env, void *data);

void ActivateOACallbackCompletedCB(napi_env env, napi_status status, void *data);

void CBOrPromiseToActivateOA(napi_env env, const ActivateOAAsyncContext *activateOA, napi_value err, napi_value data);

napi_value ParseParaCreateOA(napi_env env, napi_callback_info cbInfo, CreateOAAsyncContext *createOACB);

void CreateOAExecuteCB(napi_env env, void *data);

void CreateOACallbackCompletedCB(napi_env env, napi_status status, void *data);

void CBOrPromiseToCreateOA(napi_env env, const CreateOAAsyncContext *createOACB, napi_value err, napi_value data);

void ParseParaGetOACount(napi_env env, napi_callback_info cbInfo, GetOACountAsyncContext *getOACount);

void GetOACountExecuteCB(napi_env env, void *data);

void GetOACountCallbackCompletedCB(napi_env env, napi_status status, void *data);

void CBOrPromiseToGetOACount(napi_env env, const GetOACountAsyncContext *getOACount, napi_value err, napi_value data);

void ParseParaDbDeviceId(napi_env env, napi_callback_info cbInfo, DbDeviceIdAsyncContext *dbDeviceId);

void DbDeviceIdExecuteCB(napi_env env, void *data);

void DbDeviceIdCallbackCompletedCB(napi_env env, napi_status status, void *data);

void CBOrPromiseToDbDeviceId(napi_env env, const DbDeviceIdAsyncContext *dbDeviceId, napi_value err, napi_value data);

napi_value ParseParaGetAllCons(napi_env env, napi_callback_info cbInfo, GetAllConsAsyncContext *getAllConsCB);

void GetAllConsExecuteCB(napi_env env, void *data);

void GetAllConsCallbackCompletedCB(napi_env env, napi_status status, void *data);

void GetAllAccountCons(napi_env env, const std::vector<std::string> &info, napi_value result);

void CBOrPromiseToGetAllCons(napi_env env, const GetAllConsAsyncContext *getAllCons, napi_value err, napi_value data);

void ParseParaProcessId(napi_env env, napi_callback_info cbInfo, GetIdAsyncContext *getIdCB);

void GetProcessIdExecuteCB(napi_env env, void *data);

void GetProcessIdCallbackCompletedCB(napi_env env, napi_status status, void *data);

void CBOrPromiseToGetProcessId(napi_env env, const GetIdAsyncContext *getIdCB, napi_value err, napi_value data);

void ParseQueryAllCreateOA(napi_env env, napi_callback_info cbInfo, QueryCreateOAAsyncContext *queryAllOA);

void QueryCreateOAExecuteCB(napi_env env, void *data);

void QueryCreateOACallbackCompletedCB(napi_env env, napi_status status, void *data);

void QueryOAInfoForResult(napi_env env, const std::vector<OsAccountInfo> &info, napi_value result);

void CBOrPromiseToQueryOA(napi_env env, const QueryCreateOAAsyncContext *queryOA, napi_value err, napi_value data);

napi_value ParseParaGetPhote(napi_env env, napi_callback_info cbInfo, GetOAPhotoAsyncContext *getPhoto);

void GetOAPhoteExecuteCB(napi_env env, void *data);

void GetOAPhoteCallbackCompletedCB(napi_env env, napi_status status, void *data);

void CBOrPromiseToGetPhoto(napi_env env, const GetOAPhotoAsyncContext *getPhoto, napi_value err, napi_value data);

void ParseParaCurrentOA(napi_env env, napi_callback_info cbInfo, CurrentOAAsyncContext *currentOA);

void QueryCurrentOAExecuteCB(napi_env env, void *data);

void QueryCurrentOACallbackCompletedCB(napi_env env, napi_status status, void *data);

void CBOrPromiseQueryCurrentOA(napi_env env, const CurrentOAAsyncContext *currentOA, napi_value err, napi_value data);

napi_value ParseParaGetIdByUid(napi_env env, napi_callback_info cbInfo, GetIdByUidAsyncContext *idByUid);

void GetIdByUidExecuteCB(napi_env env, void *data);

void GetIdByUidCallbackCompletedCB(napi_env env, napi_status status, void *data);

void CBOrPromiseGetIdByUid(napi_env env, const GetIdByUidAsyncContext *idByUid, napi_value err, napi_value data);

napi_value ParseParaSetPhoto(napi_env env, napi_callback_info cbInfo, SetOAPhotoAsyncContext *setPhoto);

void SetPhotoExecuteCB(napi_env env, void *data);

void SetPhotoCompletedCB(napi_env env, napi_status status, void *data);

void CBOrPromiseSetPhoto(napi_env env, const SetOAPhotoAsyncContext *setPhoto, napi_value err, napi_value data);

void ParseParaQueryMaxNum(napi_env env, napi_callback_info cbInfo, QueryMaxNumAsyncContext *maxNum);

void QueryMaxNumExecuteCB(napi_env env, void *data);

void QueryMaxNumCompletedCB(napi_env env, napi_status status, void *data);

void CBOrPromiseMaxNum(napi_env env, const QueryMaxNumAsyncContext *maxNum, napi_value err, napi_value data);

napi_value ParseParaIsActived(napi_env env, napi_callback_info cbInfo, IsActivedAsyncContext *isActived);

void IsActivedExecuteCB(napi_env env, void *data);

void IsActivedCompletedCB(napi_env env, napi_status status, void *data);

void CBOrPromiseIsActived(napi_env env, const IsActivedAsyncContext *isActived, napi_value err, napi_value data);

napi_value ParseParaIsEnable(napi_env env, napi_callback_info cbInfo, IsConEnableAsyncContext *isEnable);

void IsEnableExecuteCB(napi_env env, void *data);

void IsEnableCompletedCB(napi_env env, napi_status status, void *data);

void CBOrPromiseIsEnable(napi_env env, const IsConEnableAsyncContext *isEnable, napi_value err, napi_value data);

void ParseParaGetType(napi_env env, napi_callback_info cbInfo, GetTypeAsyncContext *getType);

void GetTypeExecuteCB(napi_env env, void *data);

void GetTypeCompletedCB(napi_env env, napi_status status, void *data);

void CBOrPromiseGetType(napi_env env, const GetTypeAsyncContext *getType, napi_value err, napi_value data);

void ParseParaIsMultiEn(napi_env env, napi_callback_info cbInfo, IsMultiEnAsyncContext *multiEn);

void IsMultiEnExecuteCB(napi_env env, void *data);

void IsMultiEnCompletedCB(napi_env env, napi_status status, void *data);

void CBOrPromiseIsMultiEn(napi_env env, const IsMultiEnAsyncContext *multiEn, napi_value err, napi_value data);

napi_value ParseParaIsVerified(napi_env env, napi_callback_info cbInfo, IsVerifiedAsyncContext *isVerified);

void IsVerifiedExecuteCB(napi_env env, void *data);

void IsVerifiedCompletedCB(napi_env env, napi_status status, void *data);

void CBOrPromiseIsVerified(napi_env env, const IsVerifiedAsyncContext *isVerified, napi_value err, napi_value data);

napi_value ParseParaSerialNumId(napi_env env, napi_callback_info cbInfo, GetSerialNumIdCBInfo *serialNumId);

void SerialNumIdExecuteCB(napi_env env, void *data);

void SerialNumIdCompletedCB(napi_env env, napi_status status, void *data);

void CBOrPromiseSerialNum(napi_env env, const GetSerialNumIdCBInfo *serialNumId, napi_value err, napi_value data);

napi_value ParseParaGetSerialNum(napi_env env, napi_callback_info cbInfo, GetSerialNumForOAInfo *getSerialNum);

void GetSerialNumExecuteCB(napi_env env, void *data);

void GetSerialNumCompletedCB(napi_env env, napi_status status, void *data);

void CBOrPromiseGetSerialNum(napi_env env, const GetSerialNumForOAInfo *getSerialNum, napi_value err, napi_value data);

void ParseParaIsTestOA(napi_env env, napi_callback_info cbInfo, IsTestOAInfo *isTest);

void CBOrPromiseIsTestOA(napi_env env, const IsTestOAInfo *isTest, napi_value err, napi_value data);

napi_value ParseParaToSubscriber(const napi_env &env, const napi_value (&argv)[ARGS_SIZE_THREE], napi_ref &callback,
    OS_ACCOUNT_SUBSCRIBE_TYPE &onType, std::string &onName);

void SubscribeExecuteCB(napi_env env, void *data);

void SubscribeCompletedCB(napi_env env, napi_status status, void *data);

napi_value ParseParaToUnsubscriber(const napi_env &env, const size_t &argc, const napi_value (&argv)[ARGS_SIZE_THREE],
    napi_ref &callback, OS_ACCOUNT_SUBSCRIBE_TYPE &offType, std::string &offName);
}  // namespace AccountJsKit
}  // namespace OHOS
#endif  // NAPI_OS_ACCOUNT_COMMON_H