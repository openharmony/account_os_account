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
#include "ability_info.h"
#include "account_error_no.h"
#include "account_log_wrapper.h"
#include "nlohmann/json.hpp"
#include "securec.h"

namespace OHOS {
namespace AccountSA {
namespace {
const int32_t ASHMEM_LEN = 16;
const std::string KEY_ABILITY_NAME = "name";
const std::string KEY_BUNDLE_NAME = "bundleName";
const std::string KEY_LABEL_ID = "labelId";
const std::string KEY_ICON_ID = "iconId";
const std::string KEY_TYPE = "type";
const std::string KEY_VISIBLE = "visible";

inline void ClearAshmem(sptr<Ashmem> &optMem)
{
    if (optMem != nullptr) {
        optMem->UnmapAshmem();
        optMem->CloseAshmem();
    }
}

bool ParseStr(const char *buf, const int itemLen, int index, std::string &result)
{
    ACCOUNT_LOGD("ParseStr itemLen:%{public}d index:%{public}d.", itemLen, index);
    if (buf == nullptr || itemLen <= 0 || index < 0) {
        ACCOUNT_LOGE("param invalid.");
        return false;
    }

    char item[itemLen + 1];
    if (strncpy_s(item, sizeof(item), buf + index, itemLen) != 0) {
        ACCOUNT_LOGE("ParseStr failed due to strncpy_s error.");
        return false;
    }

    std::string str(item, 0, itemLen);
    result = str;
    return true;
}

template<typename T>
bool ParseInfo(std::string &infoStr, T &info)
{
    nlohmann::json jsonObject = nlohmann::json::parse(infoStr.c_str(), nullptr, false);
    if (jsonObject.is_discarded()) {
        ACCOUNT_LOGE("failed due to data is discarded");
        return false;
    }
    if ((jsonObject.find(KEY_BUNDLE_NAME) != jsonObject.end()) && jsonObject.at(KEY_BUNDLE_NAME).is_string()) {
        info.bundleName = jsonObject.at(KEY_BUNDLE_NAME).get<std::string>();
    }
    if ((jsonObject.find(KEY_ABILITY_NAME) != jsonObject.end()) && jsonObject.at(KEY_BUNDLE_NAME).is_string()) {
        info.name = jsonObject.at(KEY_ABILITY_NAME).get<std::string>();
    }
    if ((jsonObject.find(KEY_TYPE) != jsonObject.end()) && jsonObject.at(KEY_TYPE).is_number()) {
        info.type = AppExecFwk::AbilityType(jsonObject.at(KEY_TYPE).get<int32_t>());
    }
    if ((jsonObject.find(KEY_LABEL_ID) != jsonObject.end()) && jsonObject.at(KEY_LABEL_ID).is_number()) {
        info.labelId = jsonObject.at(KEY_LABEL_ID).get<int32_t>();
    }
    if ((jsonObject.find(KEY_ICON_ID) != jsonObject.end()) && jsonObject.at(KEY_ICON_ID).is_number()) {
        info.iconId = jsonObject.at(KEY_ICON_ID).get<int32_t>();
    }
    if ((jsonObject.find(KEY_VISIBLE) != jsonObject.end()) && jsonObject.at(KEY_VISIBLE).is_boolean()) {
        info.visible = jsonObject.at(KEY_VISIBLE).get<bool>();
    }
    return true;
}
}

BundleManagerAdapterProxy::BundleManagerAdapterProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<IBundleMgr>(impl)
{}

BundleManagerAdapterProxy::~BundleManagerAdapterProxy()
{}

bool BundleManagerAdapterProxy::GetBundleInfo(
    const std::string &bundleName, const BundleFlag flag, BundleInfo &bundleInfo, int32_t userId)
{
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
    return uid;
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

bool BundleManagerAdapterProxy::QueryAbilityInfos(
    const Want &want, int32_t flags, int32_t userId, std::vector<AbilityInfo> &abilityInfos)
{
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

    if (!GetParcelableInfosFromAshmem<AbilityInfo>(IBundleMgr::Message::QUERY_ABILITY_INFOS_MUTI_PARAM,
                                                   data, abilityInfos)) {
        ACCOUNT_LOGE("fail to QueryAbilityInfos from server");
        return false;
    }
    return true;
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

bool BundleManagerAdapterProxy::QueryExtensionAbilityInfos(const Want &want, const int32_t &flag,
    const int32_t &userId, std::vector<ExtensionAbilityInfo> &extensionInfos)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("fail to QueryExtensionAbilityInfos due to write InterfaceToken fail");
        return false;
    }
    if (!data.WriteParcelable(&want)) {
        ACCOUNT_LOGE("fail to QueryExtensionAbilityInfos due to write want fail");
        return false;
    }
    if (!data.WriteInt32(flag)) {
        ACCOUNT_LOGE("fail to QueryExtensionAbilityInfos due to write flag fail");
        return false;
    }
    if (!data.WriteInt32(userId)) {
        ACCOUNT_LOGE("fail to QueryExtensionAbilityInfos due to write userId fail");
        return false;
    }

    if (!GetParcelableInfos(IBundleMgr::Message::QUERY_EXTENSION_INFO_WITHOUT_TYPE, data, extensionInfos)) {
        ACCOUNT_LOGE("fail to obtain extensionInfos");
        return false;
    }
    return true;
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
    MessageParcel reply;
    if (!SendTransactCmd(code, data, reply)) {
        return false;
    }
    if (!reply.ReadBool()) {
        return false;
    }
    int32_t infoSize = reply.ReadInt32();
    sptr<Ashmem> ashmem = reply.ReadAshmem();
    if (ashmem == nullptr) {
        ACCOUNT_LOGE("Ashmem is nullptr");
        return false;
    }
    bool ret = ashmem->MapReadOnlyAshmem();
    if (!ret) {
        ACCOUNT_LOGE("Map read only ashmem fail");
        ClearAshmem(ashmem);
        return false;
    }
    int32_t offset = 0;
    const char* dataStr = static_cast<const char*>(
        ashmem->ReadFromAshmem(ashmem->GetAshmemSize(), offset));
    if (dataStr == nullptr) {
        ClearAshmem(ashmem);
        return false;
    }
    while (infoSize > 0) {
        std::string lenStr;
        if (!ParseStr(dataStr, ASHMEM_LEN, offset, lenStr)) {
            ClearAshmem(ashmem);
            return false;
        }
        int strLen = atoi(lenStr.c_str());
        offset += ASHMEM_LEN;
        std::string infoStr;
        if (!ParseStr(dataStr, strLen, offset, infoStr)) {
            ClearAshmem(ashmem);
            return false;
        }
        T info;
        if (!ParseInfo(infoStr, info)) {
            ClearAshmem(ashmem);
            return false;
        }
        parcelableInfos.emplace_back(info);
        infoSize--;
        offset += strLen;
    }
    ClearAshmem(ashmem);
    return true;
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
