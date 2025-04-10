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

#include "account_stub.h"

#include <dlfcn.h>
#include <ipc_types.h>
#include "accesstoken_kit.h"
#include "account_error_no.h"
#include "account_info.h"
#include "account_info_parcel.h"
#include "account_log_wrapper.h"
#include "account_mgr_service.h"
#include "bundle_manager_adapter.h"
#include "account_hisysevent_adapter.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "memory_guard.h"
#include "ohos_account_kits.h"
#include "account_constants.h"
#ifdef HICOLLIE_ENABLE
#include "xcollie/xcollie.h"
#endif // HICOLLIE_ENABLE

namespace OHOS {
namespace AccountSA {
namespace {
const char PERMISSION_MANAGE_USERS[] = "ohos.permission.MANAGE_LOCAL_ACCOUNTS";
const char PERMISSION_GET_LOCAL_ACCOUNTS[] = "ohos.permission.GET_LOCAL_ACCOUNTS";
const char PERMISSION_MANAGE_DISTRIBUTED_ACCOUNTS[] = "ohos.permission.MANAGE_DISTRIBUTED_ACCOUNTS";
const char PERMISSION_GET_DISTRIBUTED_ACCOUNTS[] = "ohos.permission.GET_DISTRIBUTED_ACCOUNTS";
const char PERMISSION_DISTRIBUTED_DATASYNC[] = "ohos.permission.DISTRIBUTED_DATASYNC";
const char INTERACT_ACROSS_LOCAL_ACCOUNTS[] = "ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS";
#ifndef IS_RELEASE_VERSION
constexpr std::int32_t ROOT_UID = 0;
#endif
#ifdef HICOLLIE_ENABLE
constexpr std::int32_t RECOVERY_TIMEOUT = 6; // timeout 6s
#endif // HICOLLIE_ENABLE
constexpr std::int32_t INVALID_USERID = -1;
const std::set<std::int32_t> WHITE_LIST = {
    3012, // DISTRIBUTED_KV_DATA_SA_UID
    3019, // DLP_UID
    3553, // DLP_CREDENTIAL_SA_UID
};
#ifdef USE_MUSL
constexpr std::int32_t DSOFTBUS_UID = 1024;
#else
constexpr std::int32_t DSOFTBUS_UID = 5533;
#endif
}  // namespace
AccountStub::AccountStub()
{}

ErrCode AccountStub::InnerUpdateOhosAccountInfo(MessageParcel &data, MessageParcel &reply)
{
    // ignore the real account name
    const std::string accountName = Str16ToStr8(data.ReadString16());
    if (accountName.empty()) {
        ACCOUNT_LOGE("empty account name!");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    const std::string uid = Str16ToStr8(data.ReadString16());
    if (uid.empty()) {
        ACCOUNT_LOGE("empty uid!");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    const std::string eventStr = Str16ToStr8(data.ReadString16());

    ErrCode ret = UpdateOhosAccountInfo(accountName, uid, eventStr);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("Update ohos account info failed");
        return ret;
    }
    if (!reply.WriteInt32(ret)) {
        ACCOUNT_LOGE("Write result data failed");
        ret = ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    return ret;
}

ErrCode AccountStub::InnerSetOhosAccountInfo(int32_t userId, MessageParcel &data, MessageParcel &reply)
{
    OhosAccountInfo info;
    std::int32_t ret = ReadOhosAccountInfo(data, info);
    if (ret != ERR_OK) {
        return ret;
    }
    if (!info.IsValid()) {
        ACCOUNT_LOGE("Check OhosAccountInfo failed");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    // ignore the real account name
    const std::string eventStr = Str16ToStr8(data.ReadString16());

    if (userId == INVALID_USERID) {
        userId = AccountMgrService::GetInstance().GetCallingUserID();
    }
    ret = SetOsAccountDistributedInfo(userId, info, eventStr);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("Set ohos account info failed");
    }
    if (!reply.WriteInt32(ret)) {
        ACCOUNT_LOGE("Write result data failed");
        ret = ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    return ret;
}

ErrCode AccountStub::CmdUpdateOhosAccountInfo(MessageParcel &data, MessageParcel &reply)
{
    if (!HasAccountRequestPermission(PERMISSION_MANAGE_USERS)) {
        ACCOUNT_LOGE("Check permission failed");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return InnerUpdateOhosAccountInfo(data, reply);
}

ErrCode AccountStub::CmdSetOhosAccountInfo(MessageParcel &data, MessageParcel &reply)
{
    if (!HasAccountRequestPermission(PERMISSION_MANAGE_DISTRIBUTED_ACCOUNTS)) {
        ACCOUNT_LOGE("Check permission failed");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return InnerSetOhosAccountInfo(INVALID_USERID, data, reply);
}

static int32_t CheckUserIdValid(const int32_t userId)
{
    if ((userId >= 0) && (userId < Constants::START_USER_ID)) {
        ACCOUNT_LOGE("userId %{public}d is system reserved", userId);
        return ERR_OSACCOUNT_SERVICE_MANAGER_ID_ERROR;
    }
    bool isOsAccountExist = false;
    IInnerOsAccountManager::GetInstance().IsOsAccountExists(userId, isOsAccountExist);
    if (!isOsAccountExist) {
        ACCOUNT_LOGE("os account is not exist");
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    return ERR_OK;
}

ErrCode AccountStub::CmdSetOhosAccountInfoByUserId(MessageParcel &data, MessageParcel &reply)
{
    std::int32_t ret = AccountPermissionManager::CheckSystemApp();
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("the caller is not system application, ret = %{public}d.", ret);
        return ret;
    }
    if (!HasAccountRequestPermission(PERMISSION_MANAGE_DISTRIBUTED_ACCOUNTS)) {
        ACCOUNT_LOGE("Check permission failed");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    int32_t userId = data.ReadInt32();
    ret = CheckUserIdValid(userId);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("CheckUserIdValid failed, ret = %{public}d", ret);
        return ret;
    }
    return InnerSetOhosAccountInfo(userId, data, reply);
}

ErrCode AccountStub::InnerQueryDistributedVirtualDeviceId(MessageParcel &data, MessageParcel &reply)
{
    std::string dvid = "";
    ErrCode result = QueryDistributedVirtualDeviceId(dvid);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Failed to write reply, result=%{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Failed to get dvid");
        return result;
    }
    if (!reply.WriteString(dvid)) {
        ACCOUNT_LOGE("Failed to write dvid");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return result;
}

ErrCode AccountStub::InnerQueryOhosAccountInfo(MessageParcel &data, MessageParcel &reply)
{
    OhosAccountInfo info;
#ifdef HICOLLIE_ENABLE
    unsigned int flag = HiviewDFX::XCOLLIE_FLAG_LOG | HiviewDFX::XCOLLIE_FLAG_RECOVERY;
    XCollieCallback callbackFunc = [callingPid = IPCSkeleton::GetCallingPid(),
        callingUid = IPCSkeleton::GetCallingUid()](void *) {
        ACCOUNT_LOGE("InnerQueryOhosAccountInfo failed, callingPid: %{public}d, callingUid: %{public}d.",
            callingPid, callingUid);
        ReportOhosAccountOperationFail(callingUid, "watchDog", -1, "Query ohos account info time out");
    };
    int timerId = HiviewDFX::XCollie::GetInstance().SetTimer(
        TIMER_NAME, RECOVERY_TIMEOUT, callbackFunc, nullptr, flag);
#endif // HICOLLIE_ENABLE
    ErrCode result = QueryOhosAccountInfo(info);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Query ohos account info failed");
#ifdef HICOLLIE_ENABLE
        HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
#endif // HICOLLIE_ENABLE
        return result;
    }

    std::string name = info.name_;
    std::string id = info.uid_;
    if (!reply.WriteString16(Str8ToStr16(name))) {
        ACCOUNT_LOGE("Write name data failed");
#ifdef HICOLLIE_ENABLE
        HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
#endif // HICOLLIE_ENABLE
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!reply.WriteString16(Str8ToStr16(id))) {
        ACCOUNT_LOGE("Write id data failed");
#ifdef HICOLLIE_ENABLE
        HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
#endif // HICOLLIE_ENABLE
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!reply.WriteInt32(info.status_)) {
        ACCOUNT_LOGE("Write status data failed");
#ifdef HICOLLIE_ENABLE
        HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
#endif // HICOLLIE_ENABLE
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
#ifdef HICOLLIE_ENABLE
    HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
#endif // HICOLLIE_ENABLE
    return ERR_OK;
}

ErrCode AccountStub::InnerGetOhosAccountInfo(MessageParcel &data, MessageParcel &reply)
{
    OhosAccountInfo ohosAccountInfo;
    ErrCode ret = GetOhosAccountInfo(ohosAccountInfo);
    ohosAccountInfo.SetRawUid("");
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("Get ohos account info failed");
        return ret;
    }
    if (!WriteOhosAccountInfo(reply, ohosAccountInfo)) {
        ACCOUNT_LOGE("Write ohosAccountInfo failed!");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode AccountStub::CmdQueryDVIDByBundleName(MessageParcel &data, MessageParcel &reply)
{
    ErrCode errCode = AccountPermissionManager::CheckSystemApp();
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("The caller is not system application, errCode = %{public}d.", errCode);
        return errCode;
    }
    if (!HasAccountRequestPermission(PERMISSION_MANAGE_DISTRIBUTED_ACCOUNTS) &&
        !HasAccountRequestPermission(PERMISSION_MANAGE_USERS) &&
        !HasAccountRequestPermission(PERMISSION_GET_DISTRIBUTED_ACCOUNTS)) {
        ACCOUNT_LOGE("Failed to check permission");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    std::string bundleName = "";
    if (!data.ReadString(bundleName)) {
        ACCOUNT_LOGE("Failed to read bundleName");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    int32_t localId;
    if (!data.ReadInt32(localId)) {
        ACCOUNT_LOGE("Failed to read localId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    std::string dvid = "";
    ErrCode result = QueryDistributedVirtualDeviceId(bundleName, localId, dvid);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Failed to write reply, result=%{public}d.", result);
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Failed to get dvid");
        return ERR_OK;
    }
    if (!reply.WriteString(dvid)) {
        ACCOUNT_LOGE("Failed to write dvid");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    return result;
}

ErrCode AccountStub::CmdQueryDistributedVirtualDeviceId(MessageParcel &data, MessageParcel &reply)
{
    if (!HasAccountRequestPermission(PERMISSION_MANAGE_USERS) &&
        !HasAccountRequestPermission(PERMISSION_DISTRIBUTED_DATASYNC)) {
        ACCOUNT_LOGE("Check permission failed");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    return InnerQueryDistributedVirtualDeviceId(data, reply);
}

ErrCode AccountStub::CmdQueryOhosAccountInfo(MessageParcel &data, MessageParcel &reply)
{
    if (!HasAccountRequestPermission(PERMISSION_MANAGE_USERS) &&
        !HasAccountRequestPermission(PERMISSION_DISTRIBUTED_DATASYNC) &&
        !HasAccountRequestPermission(PERMISSION_GET_LOCAL_ACCOUNTS)) {
        ACCOUNT_LOGE("Check permission failed");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return InnerQueryOhosAccountInfo(data, reply);
}

ErrCode AccountStub::CmdGetOhosAccountInfo(MessageParcel &data, MessageParcel &reply)
{
    if (!HasAccountRequestPermission(PERMISSION_MANAGE_DISTRIBUTED_ACCOUNTS) &&
        !HasAccountRequestPermission(PERMISSION_DISTRIBUTED_DATASYNC) &&
        !HasAccountRequestPermission(PERMISSION_GET_DISTRIBUTED_ACCOUNTS)) {
        ACCOUNT_LOGE("Check permission failed");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    return InnerGetOhosAccountInfo(data, reply);
}

ErrCode AccountStub::CmdGetOhosAccountInfoByUserId(MessageParcel &data, MessageParcel &reply)
{
    ErrCode errCode = AccountPermissionManager::CheckSystemApp();
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("the caller is not system application, errCode = %{public}d.", errCode);
        return errCode;
    }
    if (!HasAccountRequestPermission(PERMISSION_MANAGE_DISTRIBUTED_ACCOUNTS) &&
        !HasAccountRequestPermission(INTERACT_ACROSS_LOCAL_ACCOUNTS) &&
        !HasAccountRequestPermission(PERMISSION_DISTRIBUTED_DATASYNC) &&
        !HasAccountRequestPermission(PERMISSION_GET_DISTRIBUTED_ACCOUNTS)) {
        ACCOUNT_LOGE("Check permission failed");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }
    int32_t userId = data.ReadInt32();
    bool isOsAccountExits = false;
    errCode = IInnerOsAccountManager::GetInstance().IsOsAccountExists(userId, isOsAccountExits);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("IsOsAccountExists failed errCode is %{public}d", errCode);
        return errCode;
    }
    if (!isOsAccountExits) {
        ACCOUNT_LOGE("os account is not exit");
        return ERR_ACCOUNT_COMMON_ACCOUNT_NOT_EXIST_ERROR;
    }
    OhosAccountInfo ohosAccountInfo;
    errCode = GetOsAccountDistributedInfo(userId, ohosAccountInfo);
    if (errCode != ERR_OK) {
        ACCOUNT_LOGE("Get ohos account info failed");
        return errCode;
    }
    int32_t uid = IPCSkeleton::GetCallingUid();
    if (WHITE_LIST.find(uid) == WHITE_LIST.end()) {
        ohosAccountInfo.SetRawUid("");
    }
    if (!WriteOhosAccountInfo(reply, ohosAccountInfo)) {
        ACCOUNT_LOGE("Write ohosAccountInfo failed!");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode AccountStub::CmdQueryOhosAccountInfoByUserId(MessageParcel &data, MessageParcel &reply)
{
    if ((!HasAccountRequestPermission(PERMISSION_MANAGE_USERS)) &&
        (!HasAccountRequestPermission(PERMISSION_DISTRIBUTED_DATASYNC)) &&
        (IPCSkeleton::GetCallingUid() != DSOFTBUS_UID)) {
        ACCOUNT_LOGE("Check permission failed");
        REPORT_PERMISSION_FAIL();
        return ERR_ACCOUNT_COMMON_PERMISSION_DENIED;
    }

    std::int32_t userId = data.ReadInt32();
    if (userId < 0) {
        ACCOUNT_LOGE("negative userID %{public}d detected!", userId);
        return ERR_ACCOUNT_ZIDL_ACCOUNT_STUB_USERID_ERROR;
    }

    OhosAccountInfo info;
    ErrCode result = QueryOsAccountDistributedInfo(userId, info);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Query ohos account info failed! userId %{public}d.", userId);
        return result;
    }

    std::string name = info.name_;
    std::string id = info.uid_;
    if (!reply.WriteString16(Str8ToStr16(name))) {
        ACCOUNT_LOGE("Write name data failed! userId %{public}d.", userId);
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!reply.WriteString16(Str8ToStr16(id))) {
        ACCOUNT_LOGE("Write id data failed! userId %{public}d.", userId);
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!reply.WriteInt32(info.status_)) {
        ACCOUNT_LOGE("Write status data failed! userId %{public}d.", userId);
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode AccountStub::CmdQueryDeviceAccountId(MessageParcel &data, MessageParcel &reply)
{
    std::int32_t id;
    auto ret = QueryDeviceAccountId(id);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("QueryDevice AccountId failed: %{public}d", ret);
        return ret;
    }

    if (!reply.WriteInt32(id)) {
        ACCOUNT_LOGE("Write result data failed");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode AccountStub::CmdSubscribeDistributedAccountEvent(MessageParcel &data, MessageParcel &reply)
{
    int32_t type;
    if (!data.ReadInt32(type)) {
        ACCOUNT_LOGE("Read type failed.");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }

    sptr<IRemoteObject> eventListener = data.ReadRemoteObject();
    if (eventListener == nullptr) {
        ACCOUNT_LOGE("Read remote object for eventListener failed.");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }

    ErrCode result = SubscribeDistributedAccountEvent(
        static_cast<DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE>(type), eventListener);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Write reply failed, result=%{public}d.", result);
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    return ERR_OK;
}

ErrCode AccountStub::CmdUnsubscribeDistributedAccountEvent(MessageParcel &data, MessageParcel &reply)
{
    int32_t type;
    if (!data.ReadInt32(type)) {
        ACCOUNT_LOGE("Read type failed.");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }

    sptr<IRemoteObject> eventListener = data.ReadRemoteObject();
    if (eventListener == nullptr) {
        ACCOUNT_LOGE("Read remote object for eventListener failed.");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }

    ErrCode result = UnsubscribeDistributedAccountEvent(
        static_cast<DISTRIBUTED_ACCOUNT_SUBSCRIBE_TYPE>(type), eventListener);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Write reply failed, result=%{public}d.", result);
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    return ERR_OK;
}

ErrCode AccountStub::CmdGetAppAccountService(MessageParcel &data, MessageParcel &reply)
{
    auto remoteObject = GetAppAccountService();
    if (!reply.WriteRemoteObject(remoteObject)) {
        ACCOUNT_LOGE("Write result data failed");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    return ERR_OK;
}
ErrCode AccountStub::CmdGetOsAccountService(MessageParcel &data, MessageParcel &reply)
{
    auto remoteObject = GetOsAccountService();
    if (!reply.WriteRemoteObject(remoteObject)) {
        ACCOUNT_LOGE("Write result data failed");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    return ERR_OK;
}

ErrCode AccountStub::CmdGetAccountIAMService(MessageParcel &data, MessageParcel &reply)
{
    auto remoteObject = GetAccountIAMService();
    if (!reply.WriteRemoteObject(remoteObject)) {
        ACCOUNT_LOGE("Write result data failed");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    return ERR_OK;
}

ErrCode AccountStub::CmdGetDomainAccountService(MessageParcel &data, MessageParcel &reply)
{
#ifdef SUPPORT_DOMAIN_ACCOUNTS
    auto remoteObject = GetDomainAccountService();
    if (!reply.WriteRemoteObject(remoteObject)) {
        ACCOUNT_LOGE("failed to write remote object");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    return ERR_OK;
#else
    return ERR_DOMAIN_ACCOUNT_NOT_SUPPORT;
#endif // SUPPORT_DOMAIN_ACCOUNTS
}

int32_t AccountStub::ProcAccountStubRequest(
    std::uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    AccountMgrInterfaceCode interfaceCode = static_cast<AccountMgrInterfaceCode>(code);
    switch (interfaceCode) {
        case AccountMgrInterfaceCode::UPDATE_OHOS_ACCOUNT_INFO:
            return CmdUpdateOhosAccountInfo(data, reply);
        case AccountMgrInterfaceCode::SET_OHOS_ACCOUNT_INFO:
            return CmdSetOhosAccountInfo(data, reply);
        case AccountMgrInterfaceCode::SET_OHOS_ACCOUNT_INFO_BY_USER_ID:
            return CmdSetOhosAccountInfoByUserId(data, reply);
        case AccountMgrInterfaceCode::QUERY_OHOS_ACCOUNT_INFO:
            return CmdQueryOhosAccountInfo(data, reply);
        case AccountMgrInterfaceCode::QUERY_DISTRIBUTE_VIRTUAL_DEVICE_ID:
            return CmdQueryDistributedVirtualDeviceId(data, reply);
        case AccountMgrInterfaceCode::QUERY_DISTRIBUTE_VIRTUAL_DEVICE_ID_BY_BUNDLE_NAME:
            return CmdQueryDVIDByBundleName(data, reply);
        case AccountMgrInterfaceCode::GET_OHOS_ACCOUNT_INFO:
            return CmdGetOhosAccountInfo(data, reply);
        case AccountMgrInterfaceCode::QUERY_OHOS_ACCOUNT_INFO_BY_USER_ID:
            return CmdQueryOhosAccountInfoByUserId(data, reply);
        case AccountMgrInterfaceCode::GET_OHOS_ACCOUNT_INFO_BY_USER_ID:
            return CmdGetOhosAccountInfoByUserId(data, reply);
        case AccountMgrInterfaceCode::QUERY_DEVICE_ACCOUNT_ID:
            return CmdQueryDeviceAccountId(data, reply);
        case AccountMgrInterfaceCode::SUBSCRIBE_DISTRIBUTED_ACCOUNT_EVENT:
            return CmdSubscribeDistributedAccountEvent(data, reply);
        case AccountMgrInterfaceCode::UNSUBSCRIBE_DISTRIBUTED_ACCOUNT_EVENT:
            return CmdUnsubscribeDistributedAccountEvent(data, reply);
        case AccountMgrInterfaceCode::GET_APP_ACCOUNT_SERVICE:
            return CmdGetAppAccountService(data, reply);
        case AccountMgrInterfaceCode::GET_OS_ACCOUNT_SERVICE:
            return CmdGetOsAccountService(data, reply);
        case AccountMgrInterfaceCode::GET_ACCOUNT_IAM_SERVICE:
            return CmdGetAccountIAMService(data, reply);
        case AccountMgrInterfaceCode::GET_DOMAIN_ACCOUNT_SERVICE:
            return CmdGetDomainAccountService(data, reply);
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}

std::int32_t AccountStub::OnRemoteRequest(
    std::uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    ACCOUNT_LOGD("Received stub message: %{public}d, callingUid: %{public}d", code, IPCSkeleton::GetCallingUid());
    MemoryGuard cacheGuard;
    if (!IsServiceStarted()) {
        ACCOUNT_LOGE("account mgr not ready");
        return ERR_ACCOUNT_ZIDL_MGR_NOT_READY_ERROR;
    }

    if (data.ReadInterfaceToken() != GetDescriptor()) {
        ACCOUNT_LOGE("check descriptor failed! code %{public}u.", code);
        return ERR_ACCOUNT_COMMON_CHECK_DESCRIPTOR_ERROR;
    }

#ifdef HICOLLIE_ENABLE
    int timerId =
        HiviewDFX::XCollie::GetInstance().SetTimer(TIMER_NAME, TIMEOUT, nullptr, nullptr, HiviewDFX::XCOLLIE_FLAG_LOG);
#endif // HICOLLIE_ENABLE
    int32_t ret =  ProcAccountStubRequest(code, data, reply, option);
#ifdef HICOLLIE_ENABLE
    HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
#endif // HICOLLIE_ENABLE
    return ret;
}

bool AccountStub::HasAccountRequestPermission(const std::string &permissionName)
{
#ifndef IS_RELEASE_VERSION
    std::int32_t uid = IPCSkeleton::GetCallingUid();
    // root check in none release version for test
    if (uid == ROOT_UID) {
        return true;
    }
#endif

    // check permission
    Security::AccessToken::AccessTokenID callingTokenID = IPCSkeleton::GetCallingTokenID();
    if (Security::AccessToken::AccessTokenKit::VerifyAccessToken(callingTokenID, permissionName) ==
        Security::AccessToken::TypePermissionState::PERMISSION_GRANTED) {
        return true;
    }

    return false;
}
}  // namespace AccountSA
}  // namespace OHOS
