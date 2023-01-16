/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
#include "account_helper_data.h"
#include "account_info.h"
#include "account_info_parcel.h"
#include "account_log_wrapper.h"
#include "account_mgr_service.h"
#include "bundle_manager_adapter.h"
#include "hisysevent_adapter.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "ohos_account_kits.h"

namespace OHOS {
namespace AccountSA {
namespace {
const std::string OHOS_ACCOUNT_QUIT_TIPS_TITLE = "";
const std::string OHOS_ACCOUNT_QUIT_TIPS_CONTENT = "";
const std::string PERMISSION_MANAGE_USERS = "ohos.permission.MANAGE_LOCAL_ACCOUNTS";
const std::string PERMISSION_MANAGE_DISTRIBUTED_ACCOUNTS = "ohos.permission.MANAGE_DISTRIBUTED_ACCOUNTS";
const std::string PERMISSION_GET_DISTRIBUTED_ACCOUNTS = "ohos.permission.GET_DISTRIBUTED_ACCOUNTS";
const std::string PERMISSION_DISTRIBUTED_DATASYNC = "ohos.permission.DISTRIBUTED_DATASYNC";
constexpr std::int32_t ROOT_UID = 0;
constexpr std::int32_t DLP_UID = 3019;
constexpr std::int32_t DLP_CREDENTIAL_SA_UID = 3553;
#ifdef USE_MUSL
constexpr std::int32_t DSOFTBUS_UID = 1024;
#else
constexpr std::int32_t DSOFTBUS_UID = 5533;
#endif
}  // namespace
const std::map<std::uint32_t, AccountStubFunc> AccountStub::stubFuncMap_{
    std::make_pair(UPDATE_OHOS_ACCOUNT_INFO, &AccountStub::CmdUpdateOhosAccountInfo),
    std::make_pair(SET_OHOS_ACCOUNT_INFO, &AccountStub::CmdSetOhosAccountInfo),
    std::make_pair(QUERY_OHOS_ACCOUNT_INFO, &AccountStub::CmdQueryOhosAccountInfo),
    std::make_pair(GET_OHOS_ACCOUNT_INFO, &AccountStub::CmdGetOhosAccountInfo),
    std::make_pair(QUERY_OHOS_ACCOUNT_QUIT_TIPS, &AccountStub::CmdQueryOhosQuitTips),
    std::make_pair(QUERY_OHOS_ACCOUNT_INFO_BY_USER_ID, &AccountStub::CmdQueryOhosAccountInfoByUserId),
    std::make_pair(GET_OHOS_ACCOUNT_INFO_BY_USER_ID, &AccountStub::CmdGetOhosAccountInfoByUserId),
    std::make_pair(QUERY_DEVICE_ACCOUNT_ID, &AccountStub::CmdQueryDeviceAccountId),
    std::make_pair(GET_APP_ACCOUNT_SERVICE, &AccountStub::CmdGetAppAccountService),
    std::make_pair(GET_OS_ACCOUNT_SERVICE, &AccountStub::CmdGetOsAccountService),
    std::make_pair(GET_ACCOUNT_IAM_SERVICE, &AccountStub::CmdGetAccountIAMService),
    std::make_pair(GET_DOMAIN_ACCOUNT_SERVICE, &AccountStub::CmdGetDomainAccountService),
};

std::int32_t AccountStub::InnerUpdateOhosAccountInfo(MessageParcel &data, MessageParcel &reply)
{
    // ignore the real account name
    const std::string accountName = Str16ToStr8(data.ReadString16());
    if (accountName.empty()) {
        ACCOUNT_LOGE("empty account name!");
        return ERR_ACCOUNT_ZIDL_ACCOUNT_STUB_ERROR;
    }
    const std::string uid = Str16ToStr8(data.ReadString16());
    if (uid.empty()) {
        ACCOUNT_LOGE("empty uid!");
        return ERR_ACCOUNT_ZIDL_ACCOUNT_STUB_ERROR;
    }
    const std::string eventStr = Str16ToStr8(data.ReadString16());

    std::int32_t ret = ERR_OK;
    bool result = UpdateOhosAccountInfo(accountName, uid, eventStr);
    if (!result) {
        ACCOUNT_LOGE("Update ohos account info failed");
        ret = ERR_ACCOUNT_ZIDL_ACCOUNT_STUB_ERROR;
    }
    if (!reply.WriteInt32(ret)) {
        ACCOUNT_LOGE("Write result data failed");
        ret = ERR_ACCOUNT_ZIDL_WRITE_RESULT_ERROR;
    }
    return ret;
}

std::int32_t AccountStub::InnerSetOhosAccountInfo(MessageParcel &data, MessageParcel &reply)
{
    OhosAccountInfo info;
    std::int32_t ret = ReadOhosAccountInfo(data, info);
    if (ret != ERR_OK) {
        return ret;
    }
    if (!info.IsValid()) {
        ACCOUNT_LOGE("Check OhosAccountInfo failed");
        return ERR_OHOSACCOUNT_KIT_INVALID_PARAMETER;
    }
    // ignore the real account name
    const std::string eventStr = Str16ToStr8(data.ReadString16());

    ret = SetOhosAccountInfo(info, eventStr);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("Set ohos account info failed");
        ret = ERR_ACCOUNT_ZIDL_ACCOUNT_STUB_ERROR;
    }
    if (!reply.WriteInt32(ret)) {
        ACCOUNT_LOGE("Write result data failed");
        ret = ERR_ACCOUNT_ZIDL_WRITE_RESULT_ERROR;
    }
    return ret;
}

std::int32_t AccountStub::CmdUpdateOhosAccountInfo(MessageParcel &data, MessageParcel &reply)
{
    if (!HasAccountRequestPermission(PERMISSION_MANAGE_USERS)) {
        ACCOUNT_LOGE("Check permission failed");
        return ERR_ACCOUNT_ZIDL_CHECK_PERMISSION_ERROR;
    }

    return InnerUpdateOhosAccountInfo(data, reply);
}

std::int32_t AccountStub::CmdSetOhosAccountInfo(MessageParcel &data, MessageParcel &reply)
{
    if (!HasAccountRequestPermission(PERMISSION_MANAGE_DISTRIBUTED_ACCOUNTS)) {
        ACCOUNT_LOGE("Check permission failed");
        return ERR_ACCOUNT_ZIDL_CHECK_PERMISSION_ERROR;
    }

    return InnerSetOhosAccountInfo(data, reply);
}

std::int32_t AccountStub::InnerQueryOhosAccountInfo(MessageParcel &data, MessageParcel &reply)
{
    std::pair<bool, OhosAccountInfo> info = QueryOhosAccountInfo();
    if (!info.first) {
        ACCOUNT_LOGE("Query ohos account info failed");
        return ERR_ACCOUNT_ZIDL_ACCOUNT_STUB_ERROR;
    }

    std::string name = info.second.name_;
    std::string id = info.second.uid_;
    if (!reply.WriteString16(Str8ToStr16(name))) {
        ACCOUNT_LOGE("Write name data failed");
        return ERR_ACCOUNT_ZIDL_WRITE_NAME_ERROR;
    }
    if (!reply.WriteString16(Str8ToStr16(id))) {
        ACCOUNT_LOGE("Write id data failed");
        return ERR_ACCOUNT_ZIDL_WRITE_UID_ERROR;
    }
    if (!reply.WriteInt32(info.second.status_)) {
        ACCOUNT_LOGE("Write status data failed");
        return ERR_ACCOUNT_ZIDL_WRITE_ACCOUNT_STATUS_ERROR;
    }
    return ERR_OK;
}

std::int32_t AccountStub::InnerGetOhosAccountInfo(MessageParcel &data, MessageParcel &reply)
{
    OhosAccountInfo ohosAccountInfo;
    int ret = GetOhosAccountInfo(ohosAccountInfo);
    ohosAccountInfo.SetRawUid("");
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("Get ohos account info failed");
        return ERR_ACCOUNT_ZIDL_ACCOUNT_STUB_ERROR;
    }
    if (!WriteOhosAccountInfo(reply, ohosAccountInfo)) {
        ACCOUNT_LOGE("Write ohosAccountInfo failed!");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    return ERR_OK;
}

std::int32_t AccountStub::CmdQueryOhosAccountInfo(MessageParcel &data, MessageParcel &reply)
{
    if (!HasAccountRequestPermission(PERMISSION_MANAGE_USERS) &&
        !HasAccountRequestPermission(PERMISSION_DISTRIBUTED_DATASYNC)) {
        ACCOUNT_LOGE("Check permission failed");
        return ERR_ACCOUNT_ZIDL_CHECK_PERMISSION_ERROR;
    }

    return InnerQueryOhosAccountInfo(data, reply);
}

ErrCode AccountStub::CmdGetOhosAccountInfo(MessageParcel &data, MessageParcel &reply)
{
    if (!HasAccountRequestPermission(PERMISSION_MANAGE_DISTRIBUTED_ACCOUNTS) &&
        !HasAccountRequestPermission(PERMISSION_DISTRIBUTED_DATASYNC) &&
        !HasAccountRequestPermission(PERMISSION_GET_DISTRIBUTED_ACCOUNTS)) {
        ACCOUNT_LOGE("Check permission failed");
        return ERR_ACCOUNT_ZIDL_CHECK_PERMISSION_ERROR;
    }

    return InnerGetOhosAccountInfo(data, reply);
}

ErrCode AccountStub::CmdGetOhosAccountInfoByUserId(MessageParcel &data, MessageParcel &reply)
{
    if (!HasAccountRequestPermission(PERMISSION_MANAGE_DISTRIBUTED_ACCOUNTS) &&
        !HasAccountRequestPermission(PERMISSION_DISTRIBUTED_DATASYNC) &&
        !HasAccountRequestPermission(PERMISSION_GET_DISTRIBUTED_ACCOUNTS)) {
        ACCOUNT_LOGE("Check permission failed");
        return ERR_ACCOUNT_ZIDL_CHECK_PERMISSION_ERROR;
    }
    std::int32_t userId = data.ReadInt32();
    OhosAccountInfo ohosAccountInfo;
    ErrCode ret = GetOhosAccountInfoByUserId(userId, ohosAccountInfo);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("Get ohos account info failed");
        return ret;
    }
    int32_t uid = IPCSkeleton::GetCallingUid();
    if ((uid != DLP_UID) && (uid != DLP_CREDENTIAL_SA_UID)) {
        ohosAccountInfo.SetRawUid("");
    }
    if (!WriteOhosAccountInfo(reply, ohosAccountInfo)) {
        ACCOUNT_LOGE("Write ohosAccountInfo failed!");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    return ERR_OK;
}

std::int32_t AccountStub::CmdQueryOhosAccountInfoByUserId(MessageParcel &data, MessageParcel &reply)
{
    if ((!HasAccountRequestPermission(PERMISSION_MANAGE_USERS)) &&
        (!HasAccountRequestPermission(PERMISSION_DISTRIBUTED_DATASYNC)) &&
        (IPCSkeleton::GetCallingUid() != DSOFTBUS_UID)) {
        ACCOUNT_LOGE("Check permission failed");
        return ERR_ACCOUNT_ZIDL_CHECK_PERMISSION_ERROR;
    }

    std::int32_t userId = data.ReadInt32();
    if (userId < 0) {
        ACCOUNT_LOGE("negative userID %{public}d detected!", userId);
        return ERR_ACCOUNT_ZIDL_ACCOUNT_STUB_USERID_ERROR;
    }

    std::pair<bool, OhosAccountInfo> info = QueryOhosAccountInfoByUserId(userId);
    if (!info.first) {
        ACCOUNT_LOGE("Query ohos account info failed! userId %{public}d.", userId);
        return ERR_ACCOUNT_ZIDL_ACCOUNT_STUB_ERROR;
    }

    std::string name = info.second.name_;
    std::string id = info.second.uid_;
    if (!reply.WriteString16(Str8ToStr16(name))) {
        ACCOUNT_LOGE("Write name data failed! userId %{public}d.", userId);
        return ERR_ACCOUNT_ZIDL_WRITE_NAME_ERROR;
    }
    if (!reply.WriteString16(Str8ToStr16(id))) {
        ACCOUNT_LOGE("Write id data failed! userId %{public}d.", userId);
        return ERR_ACCOUNT_ZIDL_WRITE_UID_ERROR;
    }
    if (!reply.WriteInt32(info.second.status_)) {
        ACCOUNT_LOGE("Write status data failed! userId %{public}d.", userId);
        return ERR_ACCOUNT_ZIDL_WRITE_ACCOUNT_STATUS_ERROR;
    }
    return ERR_OK;
}

std::int32_t AccountStub::CmdQueryOhosQuitTips(MessageParcel &data, MessageParcel &reply)
{
    if (!HasAccountRequestPermission(PERMISSION_MANAGE_USERS) &&
        !HasAccountRequestPermission(PERMISSION_DISTRIBUTED_DATASYNC)) {
        ACCOUNT_LOGE("Check permission failed");
        return ERR_ACCOUNT_ZIDL_CHECK_PERMISSION_ERROR;
    }

    if (!reply.WriteString16(Str8ToStr16(OHOS_ACCOUNT_QUIT_TIPS_TITLE))) {
        ACCOUNT_LOGE("Write quit tips title failed");
        return ERR_ACCOUNT_ZIDL_WRITE_RESULT_ERROR;
    }
    if (!reply.WriteString16(Str8ToStr16(OHOS_ACCOUNT_QUIT_TIPS_CONTENT))) {
        ACCOUNT_LOGE("Write quit tips content failed");
        return ERR_ACCOUNT_ZIDL_WRITE_RESULT_ERROR;
    }

    return ERR_OK;
}

std::int32_t AccountStub::CmdQueryDeviceAccountId(MessageParcel &data, MessageParcel &reply)
{
    std::int32_t id;
    auto ret = QueryDeviceAccountId(id);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("QueryDevice AccountId failed: %{public}d", ret);
        return ret;
    }

    if (!reply.WriteInt32(id)) {
        ACCOUNT_LOGE("Write result data failed");
        return ERR_ACCOUNT_ZIDL_WRITE_RESULT_ERROR;
    }
    return ERR_OK;
}

std::int32_t AccountStub::CmdGetAppAccountService(MessageParcel &data, MessageParcel &reply)
{
    auto remoteObject = GetAppAccountService();
    if (!reply.WriteRemoteObject(remoteObject)) {
        ACCOUNT_LOGE("Write result data failed");
        return ERR_ACCOUNT_ZIDL_WRITE_RESULT_ERROR;
    }

    return ERR_OK;
}
std::int32_t AccountStub::CmdGetOsAccountService(MessageParcel &data, MessageParcel &reply)
{
    auto remoteObject = GetOsAccountService();
    if (!reply.WriteRemoteObject(remoteObject)) {
        ACCOUNT_LOGE("Write result data failed");
        return ERR_ACCOUNT_ZIDL_WRITE_RESULT_ERROR;
    }

    return ERR_OK;
}

std::int32_t AccountStub::CmdGetAccountIAMService(MessageParcel &data, MessageParcel &reply)
{
    auto remoteObject = GetAccountIAMService();
    if (!reply.WriteRemoteObject(remoteObject)) {
        ACCOUNT_LOGE("Write result data failed");
        return ERR_ACCOUNT_ZIDL_WRITE_RESULT_ERROR;
    }

    return ERR_OK;
}

std::int32_t AccountStub::CmdGetDomainAccountService(MessageParcel &data, MessageParcel &reply)
{
    auto remoteObject = GetDomainAccountService();
    if (!reply.WriteRemoteObject(remoteObject)) {
        ACCOUNT_LOGE("failed to write remote object");
        return ERR_ACCOUNT_ZIDL_WRITE_PARCEL_DATA_ERROR;
    }
    return ERR_OK;
}

std::int32_t AccountStub::OnRemoteRequest(
    std::uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (!IsServiceStarted()) {
        ACCOUNT_LOGE("account mgr not ready");
        return ERR_ACCOUNT_ZIDL_MGR_NOT_READY_ERROR;
    }

    if (data.ReadInterfaceToken() != GetDescriptor()) {
        ACCOUNT_LOGE("check descriptor failed! code %{public}u.", code);
        return ERR_ACCOUNT_COMMON_CHECK_DESCRIPTOR_ERROR;
    }

    const auto &itFunc = stubFuncMap_.find(code);
    if (itFunc != stubFuncMap_.end()) {
        return (this->*(itFunc->second))(data, reply);
    }

    ACCOUNT_LOGW("remote request unhandled: %{public}d", code);
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

bool AccountStub::HasAccountRequestPermission(const std::string &permissionName)
{
    // check root
    std::int32_t uid = IPCSkeleton::GetCallingUid();
    if (uid == ROOT_UID) {
        return true;
    }

    // check permission
    Security::AccessToken::AccessTokenID callingTokenID = IPCSkeleton::GetCallingTokenID();
    if (Security::AccessToken::AccessTokenKit::VerifyAccessToken(callingTokenID, permissionName) ==
        Security::AccessToken::TypePermissionState::PERMISSION_GRANTED) {
        return true;
    }

    // check trust list
    if (CheckCallerForTrustList()) {
        return true;
    }
    ReportPermissionFail(uid, IPCSkeleton::GetCallingPid(), permissionName);
    ACCOUNT_LOGE("permission %{public}s denied!", permissionName.c_str());
    return false;
}

bool AccountStub::CheckCallerForTrustList()
{
    std::string bundleName;
    std::int32_t uid = IPCSkeleton::GetCallingUid();
    if (!BundleManagerAdapter::GetInstance()->GetBundleNameForUid(uid, bundleName)) {
        return false;
    }

    std::vector<std::string> trustList = AccountHelperData::GetBundleNameTrustList();
    if (std::find(trustList.begin(), trustList.end(), bundleName) == trustList.end()) {
        return false;
    }

    return true;
}
}  // namespace AccountSA
}  // namespace OHOS
