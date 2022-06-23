/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "bundle_manager_adapter_proxy.h"
#include "account_error_no.h"
#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
BundleManagerAdapterProxy::BundleManagerAdapterProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<IBundleMgr>(impl)
{
    ACCOUNT_LOGD("create BundleManagerAdapterProxy instance");
}

BundleManagerAdapterProxy::~BundleManagerAdapterProxy()
{
    ACCOUNT_LOGD("destroy BundleManagerAdapterProxy instance");
}

bool BundleManagerAdapterProxy::GetApplicationInfo(
    const std::string &appName, const ApplicationFlag flag, const int userId, ApplicationInfo &appInfo)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

bool BundleManagerAdapterProxy::GetApplicationInfo(
    const std::string &appName, int32_t flags, int32_t userId, ApplicationInfo &appInfo)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

bool BundleManagerAdapterProxy::GetApplicationInfos(
    const ApplicationFlag flag, int userId, std::vector<ApplicationInfo> &appInfos)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

bool BundleManagerAdapterProxy::GetApplicationInfos(
    int32_t flags, int32_t userId, std::vector<ApplicationInfo> &appInfos)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

bool BundleManagerAdapterProxy::GetBundleInfo(
    const std::string &bundleName, const BundleFlag flag, BundleInfo &bundleInfo, int32_t userId)
{
    ACCOUNT_LOGI("begin to get bundle info of %{public}s", bundleName.c_str());
    if (bundleName.empty()) {
        ACCOUNT_LOGE("fail to GetBundleInfo due to params empty");
        return false;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("fail to GetBundleInfo due to write InterfaceToken fail");
        return false;
    }
    if (!data.WriteString(bundleName)) {
        ACCOUNT_LOGE("fail to GetBundleInfo due to write bundleName fail");
        return false;
    }
    if (!data.WriteInt32(static_cast<int>(flag))) {
        ACCOUNT_LOGE("fail to GetBundleInfo due to write flag fail");
        return false;
    }
    if (!data.WriteInt32(userId)) {
        ACCOUNT_LOGE("fail to GetBundleInfo due to write userId fail");
        return false;
    }

    if (!GetParcelableInfo<BundleInfo>(IBundleMgr::Message::GET_BUNDLE_INFO, data, bundleInfo)) {
        ACCOUNT_LOGE("fail to GetBundleInfo from server");
        return false;
    }
    return true;
}

bool BundleManagerAdapterProxy::GetBundleInfo(
    const std::string &bundleName, int32_t flags, BundleInfo &bundleInfo, int32_t userId)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

bool BundleManagerAdapterProxy::GetBundlePackInfo(
    const std::string &bundleName, const BundlePackFlag flag, BundlePackInfo &bundlePackInfo, int32_t userId)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

bool BundleManagerAdapterProxy::GetBundlePackInfo(const std::string &bundleName, int32_t flags,
    BundlePackInfo &bundlePackInfo, int32_t userId)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

bool BundleManagerAdapterProxy::GetBundleInfos(
    const BundleFlag flag, std::vector<BundleInfo> &bundleInfos, int32_t userId)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

bool BundleManagerAdapterProxy::GetBundleInfos(
    int32_t flags, std::vector<BundleInfo> &bundleInfos, int32_t userId)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

int BundleManagerAdapterProxy::GetUidByBundleName(const std::string &bundleName, const int userId)
{
    if (bundleName.empty()) {
        ACCOUNT_LOGE("failed to GetUidByBundleName due to bundleName empty");
        return AppExecFwk::Constants::INVALID_UID;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to GetUidByBundleName due to write InterfaceToken fail");
        return AppExecFwk::Constants::INVALID_UID;
    }
    if (!data.WriteString(bundleName)) {
        ACCOUNT_LOGE("failed to GetUidByBundleName due to write bundleName fail");
        return AppExecFwk::Constants::INVALID_UID;
    }
    if (!data.WriteInt32(userId)) {
        ACCOUNT_LOGE("failed to GetUidByBundleName due to write uid fail");
        return AppExecFwk::Constants::INVALID_UID;
    }

    MessageParcel reply;
    if (!SendTransactCmd(IBundleMgr::Message::GET_UID_BY_BUNDLE_NAME, data, reply)) {
        ACCOUNT_LOGE("failed to GetUidByBundleName from server");
        return AppExecFwk::Constants::INVALID_UID;
    }
    int32_t uid = reply.ReadInt32();
    ACCOUNT_LOGD("uid is %{public}d", uid);
    return uid;
}

std::string BundleManagerAdapterProxy::GetAppIdByBundleName(const std::string &bundleName, const int userId)
{
    ACCOUNT_LOGE("not support interface!");
    return "";
}

bool BundleManagerAdapterProxy::GetBundleNameForUid(const int uid, std::string &bundleName)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("fail to GetBundleNameForUid due to write InterfaceToken fail");
        return false;
    }
    if (!data.WriteInt32(uid)) {
        ACCOUNT_LOGE("fail to GetBundleNameForUid due to write uid fail");
        return false;
    }

    MessageParcel reply;
    if (!SendTransactCmd(IBundleMgr::Message::GET_BUNDLE_NAME_FOR_UID, data, reply)) {
        ACCOUNT_LOGE("fail to GetBundleNameForUid from server");
        return false;
    }
    if (!reply.ReadBool()) {
        ACCOUNT_LOGE("reply result false");
        return false;
    }
    bundleName = reply.ReadString();
    return true;
}

bool BundleManagerAdapterProxy::GetBundlesForUid(const int uid, std::vector<std::string> &bundleNames)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

bool BundleManagerAdapterProxy::GetNameForUid(const int uid, std::string &name)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

bool BundleManagerAdapterProxy::GetBundleGids(const std::string &bundleName, std::vector<int> &gids)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

bool BundleManagerAdapterProxy::GetBundleGidsByUid(const std::string &bundleName, const int &uid,
    std::vector<int> &gids)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

std::string BundleManagerAdapterProxy::GetAppType(const std::string &bundleName)
{
    ACCOUNT_LOGE("not support interface!");
    return "";
}

bool BundleManagerAdapterProxy::CheckIsSystemAppByUid(const int uid)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

bool BundleManagerAdapterProxy::GetBundleInfosByMetaData(const std::string &metaData,
    std::vector<BundleInfo> &bundleInfos)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

bool BundleManagerAdapterProxy::QueryAbilityInfo(const Want &want, AbilityInfo &abilityInfo)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

bool BundleManagerAdapterProxy::QueryAbilityInfo(const Want &want, int32_t flags, int32_t userId,
    AbilityInfo &abilityInfo, const sptr<IRemoteObject> &callBack)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

void BundleManagerAdapterProxy::UpgradeAtomicService(const Want &want, int32_t userId)
{}

bool BundleManagerAdapterProxy::QueryAbilityInfo(const Want &want, int32_t flags, int32_t userId,
    AbilityInfo &abilityInfo)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

bool BundleManagerAdapterProxy::QueryAbilityInfos(const Want &want, std::vector<AbilityInfo> &abilityInfos)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

bool BundleManagerAdapterProxy::QueryAbilityInfos(
    const Want &want, int32_t flags, int32_t userId, std::vector<AbilityInfo> &abilityInfos)
{
    ACCOUNT_LOGD("enter.");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("fail to QueryAbilityInfos due to write MessageParcel fail");
        return false;
    }
    if (!data.WriteParcelable(&want)) {
        ACCOUNT_LOGE("fail to QueryAbilityInfos due to write want fail");
        return false;
    }
    if (!data.WriteInt32(flags)) {
        ACCOUNT_LOGE("fail to QueryAbilityInfos due to write flags fail");
        return false;
    }
    if (!data.WriteInt32(userId)) {
        ACCOUNT_LOGE("fail to QueryAbilityInfos due to write userId error");
        return false;
    }

    if (!GetParcelableInfos<AbilityInfo>(IBundleMgr::Message::QUERY_ABILITY_INFOS_MUTI_PARAM, data, abilityInfos)) {
        ACCOUNT_LOGE("fail to QueryAbilityInfos from server");
        return false;
    }
    return true;
}

bool BundleManagerAdapterProxy::QueryAllAbilityInfos(const Want &want, int32_t userId,
    std::vector<AbilityInfo> &abilityInfos)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

bool BundleManagerAdapterProxy::QueryAbilityInfoByUri(const std::string &abilityUri, AbilityInfo &abilityInfo)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

bool BundleManagerAdapterProxy::QueryAbilityInfosByUri(const std::string &abilityUri,
    std::vector<AbilityInfo> &abilityInfos)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

bool BundleManagerAdapterProxy::QueryAbilityInfoByUri(
    const std::string &abilityUri, int32_t userId, AbilityInfo &abilityInfo)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

bool BundleManagerAdapterProxy::QueryKeepAliveBundleInfos(std::vector<BundleInfo> &bundleInfos)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

std::string BundleManagerAdapterProxy::GetAbilityLabel(const std::string &bundleName, const std::string &abilityName)
{
    ACCOUNT_LOGE("not support interface!");
    return "";
}

std::string BundleManagerAdapterProxy::GetAbilityLabel(const std::string &bundleName, const std::string &moduleName,
    const std::string &abilityName)
{
    ACCOUNT_LOGE("not support interface!");
    return "";
}

bool BundleManagerAdapterProxy::GetBundleArchiveInfo(const std::string &hapFilePath, const BundleFlag flag,
    BundleInfo &bundleInfo)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

bool BundleManagerAdapterProxy::GetBundleArchiveInfo(const std::string &hapFilePath, int32_t flags,
    BundleInfo &bundleInfo)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

bool BundleManagerAdapterProxy::GetHapModuleInfo(const AbilityInfo &abilityInfo, HapModuleInfo &hapModuleInfo)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

bool BundleManagerAdapterProxy::GetHapModuleInfo(const AbilityInfo &abilityInfo, int32_t userId,
    HapModuleInfo &hapModuleInfo)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

bool BundleManagerAdapterProxy::GetLaunchWantForBundle(const std::string &bundleName, Want &want)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

int BundleManagerAdapterProxy::CheckPublicKeys(const std::string &firstBundleName,
    const std::string &secondBundleName)
{
    ACCOUNT_LOGE("not support interface!");
    return -1;
}

bool BundleManagerAdapterProxy::GetPermissionDef(const std::string &permissionName, PermissionDef &permissionDef)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

bool BundleManagerAdapterProxy::HasSystemCapability(const std::string &capName)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

bool BundleManagerAdapterProxy::GetSystemAvailableCapabilities(std::vector<std::string> &systemCaps)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

bool BundleManagerAdapterProxy::IsSafeMode()
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

bool BundleManagerAdapterProxy::CleanBundleCacheFiles(
    const std::string &bundleName, const sptr<ICleanCacheCallback> &cleanCacheCallback, int32_t userId)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

bool BundleManagerAdapterProxy::CleanBundleDataFiles(const std::string &bundleName, const int userId)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

bool BundleManagerAdapterProxy::RegisterBundleStatusCallback(const sptr<IBundleStatusCallback> &bundleStatusCallback)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

bool BundleManagerAdapterProxy::ClearBundleStatusCallback(const sptr<IBundleStatusCallback> &bundleStatusCallback)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

bool BundleManagerAdapterProxy::UnregisterBundleStatusCallback()
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

bool BundleManagerAdapterProxy::DumpInfos(
    const DumpFlag flag, const std::string &bundleName, int32_t userId, std::string &result)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

bool BundleManagerAdapterProxy::IsApplicationEnabled(const std::string &bundleName)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

bool BundleManagerAdapterProxy::IsModuleRemovable(const std::string &bundleName, const std::string &moduleName)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

bool BundleManagerAdapterProxy::SetModuleRemovable(const std::string &bundleName, const std::string &moduleName,
    bool isEnable)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

bool BundleManagerAdapterProxy::GetModuleUpgradeFlag(const std::string &bundleName, const std::string &moduleName)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

bool BundleManagerAdapterProxy::SetModuleUpgradeFlag(const std::string &bundleName,
    const std::string &moduleName, int32_t upgradeFlag)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

bool BundleManagerAdapterProxy::SetApplicationEnabled(const std::string &bundleName, bool isEnable, int32_t userId)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

bool BundleManagerAdapterProxy::IsAbilityEnabled(const AbilityInfo &abilityInfo)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

bool BundleManagerAdapterProxy::SetAbilityEnabled(const AbilityInfo &abilityInfo, bool isEnabled, int32_t userId)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

bool BundleManagerAdapterProxy::GetAbilityInfo(
    const std::string &bundleName, const std::string &abilityName, AbilityInfo &abilityInfo)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

bool BundleManagerAdapterProxy::GetAbilityInfo(
    const std::string &bundleName, const std::string &moduleName,
    const std::string &abilityName, AbilityInfo &abilityInfo)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

#ifdef BUNDLE_FRAMEWORK_GRAPHICS
std::shared_ptr<Media::PixelMap> BundleManagerAdapterProxy::GetAbilityPixelMapIcon(const std::string &bundleName,
    const std::string &abilityName)
{
    ACCOUNT_LOGE("not support interface!");
    return nullptr;
}

std::shared_ptr<Media::PixelMap> BundleManagerAdapterProxy::GetAbilityPixelMapIcon(const std::string &bundleName,
    const std::string &moduleName, const std::string &abilityName)
{
    ACCOUNT_LOGE("not support interface!");
    return nullptr;
}
#endif

sptr<IBundleInstaller> BundleManagerAdapterProxy::GetBundleInstaller()
{
    ACCOUNT_LOGE("not support interface!");
    return nullptr;
}

sptr<IBundleUserMgr> BundleManagerAdapterProxy::GetBundleUserMgr()
{
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("fail to get bundle user mgr due to write InterfaceToken fail");
        return nullptr;
    }
    if (!SendTransactCmd(IBundleMgr::Message::GET_BUNDLE_USER_MGR, data, reply)) {
        return nullptr;
    }

    sptr<IRemoteObject> object = reply.ReadObject<IRemoteObject>();
    if (object == nullptr) {
        ACCOUNT_LOGE("read failed");
        return nullptr;
    }
    sptr<IBundleUserMgr> bundleUserMgr = iface_cast<IBundleUserMgr>(object);
    if (bundleUserMgr == nullptr) {
        ACCOUNT_LOGE("bundleUserMgr is nullptr");
    }

    return bundleUserMgr;
}

bool BundleManagerAdapterProxy::GetAllFormsInfo(std::vector<FormInfo> &formInfos)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

bool BundleManagerAdapterProxy::GetFormsInfoByApp(const std::string &bundleName, std::vector<FormInfo> &formInfos)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

bool BundleManagerAdapterProxy::GetFormsInfoByModule(
    const std::string &bundleName, const std::string &moduleName, std::vector<FormInfo> &formInfos)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

bool BundleManagerAdapterProxy::GetShortcutInfos(const std::string &bundleName,
    std::vector<ShortcutInfo> &shortcutInfos)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

bool BundleManagerAdapterProxy::GetAllCommonEventInfo(const std::string &eventKey,
    std::vector<CommonEventInfo> &commonEventInfos)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

bool BundleManagerAdapterProxy::GetDistributedBundleInfo(const std::string &networkId, const std::string &bundleName,
    DistributedBundleInfo &distributedBundleInfo)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

std::string BundleManagerAdapterProxy::GetAppPrivilegeLevel(const std::string &bundleName, int32_t userId)
{
    ACCOUNT_LOGE("not support interface!");
    return "";
}

bool BundleManagerAdapterProxy::QueryExtensionAbilityInfos(const Want &want, const int32_t &flag,
    const int32_t &userId, std::vector<ExtensionAbilityInfo> &extensionInfos)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

bool BundleManagerAdapterProxy::QueryExtensionAbilityInfos(const Want &want,
    const ExtensionAbilityType &extensionType, const int32_t &flag, const int32_t &userId,
    std::vector<ExtensionAbilityInfo> &extensionInfos)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

bool BundleManagerAdapterProxy::QueryExtensionAbilityInfos(const ExtensionAbilityType &extensionType,
    const int32_t &userId, std::vector<ExtensionAbilityInfo> &extensionInfos)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

bool BundleManagerAdapterProxy::VerifyCallingPermission(const std::string &permission)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

std::vector<std::string> BundleManagerAdapterProxy::GetAccessibleAppCodePaths(int32_t userId)
{
    std::vector<std::string> vec;
    ACCOUNT_LOGE("not support interface!");
    return vec;
}

bool BundleManagerAdapterProxy::QueryExtensionAbilityInfoByUri(const std::string &uri, int32_t userId,
    ExtensionAbilityInfo &extensionAbilityInfo)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

bool BundleManagerAdapterProxy::ImplicitQueryInfoByPriority(const Want &want, int32_t flags, int32_t userId,
    AbilityInfo &abilityInfo, ExtensionAbilityInfo &extensionInfo)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

ErrCode BundleManagerAdapterProxy::GetSandboxBundleInfo(const std::string &bundleName, int32_t appIndex,
    int32_t userId, BundleInfo &info)
{
    ACCOUNT_LOGE("not support interface!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

bool BundleManagerAdapterProxy::GetAllDependentModuleNames(const std::string &bundleName,
    const std::string &moduleName, std::vector<std::string> &dependentModuleNames)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

template<typename T>
bool BundleManagerAdapterProxy::GetParcelableInfo(IBundleMgr::Message code, MessageParcel &data, T &parcelableInfo)
{
    MessageParcel reply;
    if (!SendTransactCmd(code, data, reply)) {
        return false;
    }

    if (!reply.ReadBool()) {
        ACCOUNT_LOGE("reply result false");
        return false;
    }

    std::unique_ptr<T> info(reply.ReadParcelable<T>());
    if (info == nullptr) {
        ACCOUNT_LOGE("readParcelableInfo failed");
        return false;
    }
    parcelableInfo = *info;
    ACCOUNT_LOGI("get parcelable info success");
    return true;
}

template <typename T>
ErrCode BundleManagerAdapterProxy::GetParcelableInfoWithErrCode(IBundleMgr::Message code, MessageParcel &data,
    T &parcelableInfo)
{
    ACCOUNT_LOGE("not support interface!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

template<typename T>
bool BundleManagerAdapterProxy::GetParcelableInfos(IBundleMgr::Message code, MessageParcel &data,
    std::vector<T> &parcelableInfos)
{
    MessageParcel reply;
    if (!SendTransactCmd(code, data, reply)) {
        return false;
    }

    if (!reply.ReadBool()) {
        ACCOUNT_LOGE("readParcelableInfo failed");
        return false;
    }

    int32_t infoSize = reply.ReadInt32();
    for (int32_t i = 0; i < infoSize; i++) {
        std::unique_ptr<T> info(reply.ReadParcelable<T>());
        if (info == nullptr) {
            ACCOUNT_LOGE("Read Parcelable infos failed");
            return false;
        }
        parcelableInfos.emplace_back(*info);
    }
    ACCOUNT_LOGI("get parcelable infos success");
    return true;
}

template <typename T>
bool BundleManagerAdapterProxy::GetParcelableInfosFromAshmem(
    IBundleMgr::Message code, MessageParcel &data, std::vector<T> &parcelableInfos)
{
    ACCOUNT_LOGE("not support interface!");
    return false;
}

bool BundleManagerAdapterProxy::SendTransactCmd(IBundleMgr::Message code, MessageParcel &data, MessageParcel &reply)
{
    MessageOption option(MessageOption::TF_SYNC);

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        ACCOUNT_LOGE("fail to send transact cmd %{public}d due to remote object", code);
        return false;
    }
    int32_t result = remote->SendRequest(code, data, reply, option);
    if (result != NO_ERROR) {
        ACCOUNT_LOGE("receive error transact code %{public}d in transact cmd %{public}d", result, code);
        return false;
    }
    return true;
}
}  // namespace AccountSA
}  // namespace OHOS
