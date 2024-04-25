/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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
constexpr int INVALID_LOCALID = -1;
constexpr std::int32_t ARGS_SIZE_ZERO = 0;
constexpr std::int32_t ARGS_SIZE_ONE = 1;
constexpr std::int32_t ARGS_SIZE_TWO = 2;
constexpr std::int32_t ARGS_SIZE_THREE = 3;
constexpr std::int32_t ARGS_SIZE_FOUR = 4;

class NapiCreateDomainCallback final : public DomainAccountCallback {
public:
    NapiCreateDomainCallback(napi_env env, napi_ref callbackRef, napi_deferred deferred);
    void OnResult(const int32_t errCode, Parcel &parcel) override;

private:
    napi_env env_ = nullptr;
    napi_ref callbackRef_ = nullptr;
    napi_deferred deferred_ = nullptr;
    AccountJsKit::ThreadLockInfo lockInfo_;
};

napi_value WrapVoidToJS(napi_env env);

bool ParseParaQueryOAByIdCB(napi_env env, napi_callback_info cbInfo, QueryOAByIdAsyncContext *asyncContext);

void QueryOAByIdExecuteCB(napi_env env, void *data);

void QueryOAByIdCallbackCompletedCB(napi_env env, napi_status status, void *data);

void GetOACBInfoToJs(napi_env env, OsAccountInfo &info, napi_value &objOAInfo);

void GetOtherAccountInfoToJs(napi_env env, OsAccountInfo &info, napi_value &objOAInfo);

void MakeArrayToJs(napi_env env, const std::vector<std::string> &constraints, napi_value jsArray);

bool ParseParaRemoveOACB(napi_env env, napi_callback_info cbInfo, RemoveOAAsyncContext *asyncContext);

void RemoveOAExecuteCB(napi_env env, void *data);

void RemoveOACallbackCompletedCB(napi_env env, napi_status status, void *data);

bool ParseParaSetOAName(napi_env env, napi_callback_info cbInfo, SetOANameAsyncContext *asyncContext);

void SetOANameExecuteCB(napi_env env, void *data);

void SetOANameCallbackCompletedCB(napi_env env, napi_status status, void *data);

bool ParseParaSetOAConstraints(napi_env env, napi_callback_info cbInfo, SetOAConsAsyncContext *asyncContext);

void SetOAConsExecuteCB(napi_env env, void *data);

void SetOAConsCallbackCompletedCB(napi_env env, napi_status status, void *data);

bool ParseParaActiveOA(napi_env env, napi_callback_info cbInfo, ActivateOAAsyncContext *asyncContext);

void ActivateOAExecuteCB(napi_env env, void *data);

void ActivateOACallbackCompletedCB(napi_env env, napi_status status, void *data);

bool ParseParaDeactivateOA(napi_env env, napi_callback_info cbInfo, ActivateOAAsyncContext *asyncContext);

void DeactivateOAExecuteCB(napi_env env, void *data);

void DeactivateOACompletedCB(napi_env env, napi_status status, void *data);

bool ParseParaCreateOA(napi_env env, napi_callback_info cbInfo, CreateOAAsyncContext *asyncContext);

bool ParseParaCreateOAForDomain(napi_env env, napi_callback_info cbInfo,
    CreateOAForDomainAsyncContext *asyncContext);

void CreateOAExecuteCB(napi_env env, void *data);

void CreateOAForDomainExecuteCB(napi_env env, void *data);

void CreateOAForDomainCompletedCB(napi_env env, napi_status status, void *data);

void CreateOACallbackCompletedCB(napi_env env, napi_status status, void *data);

void CreateOAForDomainCallbackCompletedWork(uv_work_t *work, int status);

bool ParseParaGetOACount(napi_env env, napi_callback_info cbInfo, GetOACountAsyncContext *asyncContext);

void GetOACountExecuteCB(napi_env env, void *data);

void GetOACountCallbackCompletedCB(napi_env env, napi_status status, void *data);

bool ParseParaDbDeviceId(napi_env env, napi_callback_info cbInfo, DbDeviceIdAsyncContext *asyncContext);

void DbDeviceIdExecuteCB(napi_env env, void *data);

void DbDeviceIdCallbackCompletedCB(napi_env env, napi_status status, void *data);

bool ParseParaGetAllCons(napi_env env, napi_callback_info cbInfo, GetAllConsAsyncContext *asyncContext);

void GetAllConsExecuteCB(napi_env env, void *data);

void GetAllConsCallbackCompletedCB(napi_env env, napi_status status, void *data);

void GetAllAccountCons(napi_env env, const std::vector<std::string> &info, napi_value &result);

bool ParseParaProcessId(napi_env env, napi_callback_info cbInfo, GetIdAsyncContext *asyncContext);

void GetProcessIdExecuteCB(napi_env env, void *data);

void GetProcessIdCallbackCompletedCB(napi_env env, napi_status status, void *data);

bool ParseQueryAllCreateOA(napi_env env, napi_callback_info cbInfo, QueryCreateOAAsyncContext *asyncContext);

bool ParseQueryActiveIds(napi_env env, napi_callback_info cbInfo, QueryActiveIdsAsyncContext *asyncContext);

void QueryCreateOAExecuteCB(napi_env env, void *data);

void QueryActiveIdsExecuteCB(napi_env env, void *data);

void QueryCreateOACallbackCompletedCB(napi_env env, napi_status status, void *data);

void QueryActiveIdsCallbackCompletedCB(napi_env env, napi_status status, void *data);

void GetForegroundOALocalIdExecuteCB(napi_env env, void *data);

void GetForegroundOALocalIdCallbackCompletedCB(napi_env env, napi_status status, void *data);

void QueryOAInfoForResult(napi_env env, const std::vector<OsAccountInfo> &info, napi_value &result);

bool ParseParaGetPhoto(napi_env env, napi_callback_info cbInfo, GetOAPhotoAsyncContext *asyncContext);

void GetOsAccountNameExecuteCB(napi_env env, void *data);

void GetOsAccountNameCallbackCompletedCB(napi_env env, napi_status status, void *data);

void GetOAPhotoExecuteCB(napi_env env, void *data);

void GetOAPhotoCallbackCompletedCB(napi_env env, napi_status status, void *data);

bool ParseParaCurrentOA(napi_env env, napi_callback_info cbInfo, CurrentOAAsyncContext *asyncContext);

void QueryCurrentOAExecuteCB(napi_env env, void *data);

void QueryCurrentOACallbackCompletedCB(napi_env env, napi_status status, void *data);

bool ParseParaGetIdByUid(napi_env env, napi_callback_info cbInfo, GetIdByUidAsyncContext *asyncContext);

bool ParseParaGetIdByDomain(napi_env env, napi_callback_info cbInfo, GetIdByDomainAsyncContext *asyncContext);

void GetIdByUidExecuteCB(napi_env env, void *data);

void GetBundleIdByUidExecuteCB(napi_env env, void *data);

void GetIdByDomainExecuteCB(napi_env env, void *data);

void GetIdByUidCallbackCompletedCB(napi_env env, napi_status status, void *data);

void GetBundleIdByUidCallbackCompletedCB(napi_env env, napi_status status, void *data);

void GetIdByDomainCallbackCompletedCB(napi_env env, napi_status status, void *data);

bool ParseParaSetPhoto(napi_env env, napi_callback_info cbInfo, SetOAPhotoAsyncContext *asyncContext);

void SetPhotoExecuteCB(napi_env env, void *data);

void SetPhotoCompletedCB(napi_env env, napi_status status, void *data);

bool ParseParaQueryMaxNum(napi_env env, napi_callback_info cbInfo, QueryMaxNumAsyncContext *asyncContext);

void QueryMaxNumExecuteCB(napi_env env, void *data);

void QueryMaxNumCompletedCB(napi_env env, napi_status status, void *data);

bool ParseParaIsActived(napi_env env, napi_callback_info cbInfo, IsActivedAsyncContext *asyncContext);

void IsActivedExecuteCB(napi_env env, void *data);

void IsActivedCompletedCB(napi_env env, napi_status status, void *data);

bool ParseParaIsEnable(napi_env env, napi_callback_info cbInfo, IsConEnableAsyncContext *asyncContext);

void IsEnableExecuteCB(napi_env env, void *data);

void IsEnableCompletedCB(napi_env env, napi_status status, void *data);

bool ParseParaGetType(napi_env env, napi_callback_info cbInfo, GetTypeAsyncContext *asyncContext);

void GetTypeExecuteCB(napi_env env, void *data);

void GetTypeCompletedCB(napi_env env, napi_status status, void *data);

bool ParseParaIsMultiEn(napi_env env, napi_callback_info cbInfo, IsMultiEnAsyncContext *asyncContext);

void IsMultiEnExecuteCB(napi_env env, void *data);

void IsMultiEnCompletedCB(napi_env env, napi_status status, void *data);

bool ParseParaIsVerified(napi_env env, napi_callback_info cbInfo, IsVerifiedAsyncContext *asyncContext);

void IsVerifiedExecuteCB(napi_env env, void *data);

void IsVerifiedCompletedCB(napi_env env, napi_status status, void *data);

bool ParseParaSerialNumId(napi_env env, napi_callback_info cbInfo, GetSerialNumIdCBInfo *asyncContext);

void SerialNumIdExecuteCB(napi_env env, void *data);

void SerialNumIdCompletedCB(napi_env env, napi_status status, void *data);

bool ParseParaGetSerialNum(napi_env env, napi_callback_info cbInfo, GetSerialNumForOAInfo *asyncContext);

void GetSerialNumExecuteCB(napi_env env, void *data);

void GetSerialNumCompletedCB(napi_env env, napi_status status, void *data);

bool ParseParaIsTestOA(napi_env env, napi_callback_info cbInfo, IsTestOAInfo *asyncContext);

bool ParseParaIsMainOA(napi_env env, napi_callback_info cbInfo, IsMainOAInfo *asyncContext);

bool ParseParaToSubscriber(const napi_env &env, napi_callback_info cbInfo, SubscribeCBInfo *asyncContext,
                           napi_value *thisVar);

void SubscribeExecuteCB(napi_env env, void *data);

void SubscribeCompletedCB(napi_env env, napi_status status, void *data);

bool ParseParaToUnsubscriber(
    const napi_env &env, napi_callback_info cbInfo, UnsubscribeCBInfo *asyncContext, napi_value *thisVar);

bool ParseQueryOAConstraintSrcTypes(napi_env env, napi_callback_info cbInfo,
    QueryOAConstraintSrcTypeContext *asyncContext);

void QueryOAContSrcTypeExecuteCB(napi_env env, void *data);

void QueryOAContSrcTypeCallbackCompletedCB(napi_env env, napi_status status, void *data);

void QueryOAContSrcTypeForResult(napi_env env, const std::vector<ConstraintSourceTypeInfo> &infos, napi_value &result);
}  // namespace AccountJsKit
}  // namespace OHOS

#endif  // OS_ACCOUNT_INTERFACES_KITS_NAPI_OSACCOUNT_INCLUDE_NAPI_OS_ACCOUNT_COMMON_H
