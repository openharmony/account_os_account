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
#include "json_utils.h"
#include "securec.h"
#include "string_ex.h"

namespace OHOS {
namespace AccountSA {
namespace {
const int32_t ASHMEM_LEN = 16;
const int32_t MAX_INFO_SIZE = 1048576; // 1024 x 1024
const char BUNDLE_INFO_NAME[] = "name";
const char BUNDLE_INFO_LABEL[] = "label";
const char BUNDLE_INFO_DESCRIPTION[] = "description";
const char BUNDLE_INFO_SINGLETON[] = "singleton";
const char BUNDLE_INFO_IS_NATIVE_APP[] = "isNativeApp";
const char BUNDLE_INFO_APPID[] = "appId";
const char BUNDLE_INFO_APP_INDEX[] = "appIndex";
const char BUNDLE_INFO_EXTENSION_ABILITY_INFOS[] = "extensionAbilityInfo";
const char EXTENSION_NAME[] = "name";
const char EXTENSION_LABEL[] = "label";
const char EXTENSION_DESCRIPTION[] = "description";
const char EXTENSION_TYPE[] = "type";
const char EXTENSION_VISIBLE[] = "visible";
const char EXTENSION_UID[] = "uid";
}

inline void ClearAshmem(sptr<Ashmem> &optMem)
{
    if (optMem != nullptr) {
        optMem->UnmapAshmem();
        optMem->CloseAshmem();
    }
}

bool BundleManagerAdapterProxy::ParseExtensionInfo(std::string infoStr, ExtensionAbilityInfo &extensionInfo)
{
    auto jsonObject = CreateJsonFromString(infoStr);
    if (jsonObject == nullptr) {
        ACCOUNT_LOGE("failed due to data is discarded");
        return false;
    }
    GetDataByType<std::string>(jsonObject, EXTENSION_NAME, extensionInfo.name);
    GetDataByType<std::string>(jsonObject, EXTENSION_LABEL, extensionInfo.label);
    GetDataByType<std::string>(jsonObject, EXTENSION_DESCRIPTION, extensionInfo.description);
    GetDataByType<ExtensionAbilityType>(jsonObject, EXTENSION_TYPE, extensionInfo.type);
    GetDataByType<bool>(jsonObject, EXTENSION_VISIBLE, extensionInfo.visible);
    GetDataByType<int32_t>(jsonObject, EXTENSION_UID, extensionInfo.uid);
    return true;
}

BundleManagerAdapterProxy::BundleManagerAdapterProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<IBundleMgr>(impl)
{}

BundleManagerAdapterProxy::~BundleManagerAdapterProxy()
{}

bool BundleManagerAdapterProxy::ParseStr(const char *buf, const int itemLen, int index, std::string &result)
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

bool BundleManagerAdapterProxy::ParseExtensionAbilityInfos(
    CJsonUnique &jsonObject, std::vector<ExtensionAbilityInfo> &extensionInfos)
{
    cJSON* arrayObj = GetObjFromJson(jsonObject, BUNDLE_INFO_EXTENSION_ABILITY_INFOS);
    if (!IsArray(arrayObj) || GetItemNum(arrayObj) == 0) {
        return true;
    }
    if (GetItemNum(arrayObj) > Constants::MAX_JSON_ARRAY_LENGTH) {
        ACCOUNT_LOGE("array is oversize");
        return false;
    }

    cJSON* item = nullptr;
    cJSON_ArrayForEach(item, arrayObj) {
        if (!IsObject(item)) {
            ACCOUNT_LOGE("array %{public}s exist error type info", BUNDLE_INFO_EXTENSION_ABILITY_INFOS);
            continue;
        }

        ExtensionAbilityInfo abilityInfo;
        std::string str = PackJsonToString(item);
        if (!ParseExtensionInfo(str, abilityInfo)) {
            continue;
        }
        extensionInfos.emplace_back(abilityInfo);
    }
    return true;
}

template<typename T>
bool BundleManagerAdapterProxy::ParseInfo(std::string &infoStr, T &info)
{
    auto jsonObject = CreateJsonFromString(infoStr);
    if (jsonObject == nullptr) {
        ACCOUNT_LOGE("failed due to data is discarded");
        return false;
    }

    GetDataByType<std::string>(jsonObject, BUNDLE_INFO_NAME, info.name);
    GetDataByType<std::string>(jsonObject, BUNDLE_INFO_LABEL, info.label);
    GetDataByType<std::string>(jsonObject, BUNDLE_INFO_DESCRIPTION, info.description);
    GetDataByType<bool>(jsonObject, BUNDLE_INFO_SINGLETON, info.singleton);
    GetDataByType<bool>(jsonObject, BUNDLE_INFO_IS_NATIVE_APP, info.isNativeApp);
    GetDataByType<std::string>(jsonObject, BUNDLE_INFO_APPID, info.appId);
    GetDataByType<int32_t>(jsonObject, BUNDLE_INFO_APP_INDEX, info.appIndex);
    if (!ParseExtensionAbilityInfos(jsonObject, info.extensionInfos)) {
        return false;
    }
    return true;
}

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
    return GetParcelInfo<BundleInfo>(BundleMgrInterfaceCode::GET_BUNDLE_INFO, data, bundleInfo);
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
    if (!SendTransactCmd(BundleMgrInterfaceCode::GET_UID_BY_BUNDLE_NAME, data, reply)) {
        ACCOUNT_LOGE("failed to GetUidByBundleName from server");
        return AppExecFwk::Constants::INVALID_UID;
    }
    int32_t uid = reply.ReadInt32();
    return uid;
}

ErrCode BundleManagerAdapterProxy::GetNameForUid(const int uid, std::string &bundleName)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("fail to GetNameForUid due to write InterfaceToken fail");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteInt32(uid)) {
        ACCOUNT_LOGE("fail to GetNameForUid due to write uid fail");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::GET_NAME_FOR_UID, data, reply)) {
        ACCOUNT_LOGE("fail to GetNameForUid from server");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    ErrCode result;
    if (!reply.ReadInt32(result)) {
        ACCOUNT_LOGE("reply result false");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    bundleName = reply.ReadString();
    return result;
}

ErrCode BundleManagerAdapterProxy::CreateNewBundleEl5Dir(int32_t userId)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("Fail to CreateNewBundleEl5Dir due to write interface token fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        ACCOUNT_LOGE("Fail to CreateNewBundleEl5Dir due to write userId fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::CREATE_NEW_BUNDLE_EL5_DIR, data, reply)) {
        ACCOUNT_LOGE("SendTransactCmd failed");
        return ERR_BUNDLE_MANAGER_IPC_TRANSACTION;
    }
    return reply.ReadInt32();
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

    if (!GetVectorFromParcelIntelligent<AbilityInfo>(BundleMgrInterfaceCode::QUERY_ABILITY_INFOS_MUTI_PARAM,
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
    if (!SendTransactCmd(BundleMgrInterfaceCode::GET_BUNDLE_USER_MGR, data, reply)) {
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

    if (!GetParcelableInfos(BundleMgrInterfaceCode::QUERY_EXTENSION_INFO_WITHOUT_TYPE, data, extensionInfos)) {
        ACCOUNT_LOGE("fail to obtain extensionInfos");
        return false;
    }
    return true;
}

bool BundleManagerAdapterProxy::QueryExtensionAbilityInfos(const Want &want, const ExtensionAbilityType &extensionType,
    const int32_t &flag, const int32_t &userId, std::vector<ExtensionAbilityInfo> &extensionInfos)
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
    if (!data.WriteInt32(static_cast<int32_t>(extensionType))) {
        ACCOUNT_LOGE("fail to QueryExtensionAbilityInfos due to write type fail");
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

    if (!GetParcelableInfos(BundleMgrInterfaceCode::QUERY_EXTENSION_INFO, data, extensionInfos)) {
        ACCOUNT_LOGE("fail to obtain extensionInfos");
        return false;
    }
    return true;
}

bool BundleManagerAdapterProxy::GetData(void *&buffer, size_t size, const void *data)
{
    if (data == nullptr) {
        ACCOUNT_LOGE("GetData failed duo to null data");
        return false;
    }
    if (size == 0) {
        ACCOUNT_LOGE("GetData failed duo to zero size");
        return false;
    }
    buffer = malloc(size);
    if (buffer == nullptr) {
        ACCOUNT_LOGE("GetData failed duo to malloc buffer failed");
        return false;
    }
    if (memcpy_s(buffer, size, data, size) != EOK) {
        free(buffer);
        ACCOUNT_LOGE("GetData failed duo to memcpy_s failed");
        return false;
    }
    return true;
}

template<typename T>
bool BundleManagerAdapterProxy::GetParcelInfo(BundleMgrInterfaceCode code, MessageParcel &data, T &parcelInfo)
{
    MessageParcel reply;
    if (!SendTransactCmd(code, data, reply)) {
        ACCOUNT_LOGE("SendTransactCmd failed");
        return false;
    }

    ErrCode ret = reply.ReadInt32();
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("reply result failed , ret = %{public}d", ret);
        return false;
    }

    return InnerGetParcelInfo<T>(reply, parcelInfo);
}

template<typename T>
bool BundleManagerAdapterProxy::InnerGetParcelInfo(MessageParcel &reply, T &parcelInfo)
{
    size_t dataSize = static_cast<size_t>(reply.ReadInt32());
    void *buffer = nullptr;
    if (!GetData(buffer, dataSize, reply.ReadRawData(dataSize))) {
        ACCOUNT_LOGE("GetData failed");
        return false;
    }

    MessageParcel tmpParcel;
    if (!tmpParcel.ParseFrom(reinterpret_cast<uintptr_t>(buffer), dataSize)) {
        ACCOUNT_LOGE("ParseFrom failed");
        return false;
    }

    std::unique_ptr<T> info(tmpParcel.ReadParcelable<T>());
    if (info == nullptr) {
        ACCOUNT_LOGE("ReadParcelableInfo failed");
        return false;
    }
    parcelInfo = *info;
    return true;
}

template<typename T>
bool BundleManagerAdapterProxy::GetParcelableInfo(BundleMgrInterfaceCode code, MessageParcel &data, T &parcelableInfo)
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
bool BundleManagerAdapterProxy::GetBigParcelableInfo(
    BundleMgrInterfaceCode code, MessageParcel &data, T &parcelableInfo)
{
    MessageParcel reply;
    if (!SendTransactCmd(code, data, reply)) {
        return false;
    }

    if (!reply.ReadBool()) {
        ACCOUNT_LOGE("reply result false");
        return false;
    }

    if (reply.ReadBool()) {
        ACCOUNT_LOGI("big reply, reading data from ashmem");
        return GetParcelableFromAshmem<T>(reply, parcelableInfo);
    }

    std::unique_ptr<T> info(reply.ReadParcelable<T>());
    if (info == nullptr) {
        ACCOUNT_LOGE("readParcelableInfo failed");
        return false;
    }
    parcelableInfo = *info;
    ACCOUNT_LOGD("get parcelable info success");
    return true;
}

template <typename T>
bool BundleManagerAdapterProxy::GetParcelableFromAshmem(MessageParcel &reply, T &parcelableInfo)
{
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
        ACCOUNT_LOGE("Data is nullptr when read from ashmem");
        ClearAshmem(ashmem);
        return false;
    }

    std::string lenStr;
    if (!ParseStr(dataStr, ASHMEM_LEN, offset, lenStr)) {
        ACCOUNT_LOGE("Parse lenStr fail");
        ClearAshmem(ashmem);
        return false;
    }

    int32_t strLen = 0;
    if (!StrToInt(lenStr, strLen)) {
        ACCOUNT_LOGE("Convert lenStr failed");
        ClearAshmem(ashmem);
        return false;
    }
    offset += ASHMEM_LEN;
    std::string infoStr;
    if (!ParseStr(dataStr, strLen, offset, infoStr)) {
        ACCOUNT_LOGE("Parse infoStr fail");
        ClearAshmem(ashmem);
        return false;
    }

    if (!ParseInfo(infoStr, parcelableInfo)) {
        ACCOUNT_LOGE("Parse info from json fail");
        ClearAshmem(ashmem);
        return false;
    }

    ClearAshmem(ashmem);
    ACCOUNT_LOGD("Get parcelable vector from ashmem success");
    return true;
}

template <typename T>
ErrCode BundleManagerAdapterProxy::GetParcelableInfoWithErrCode(BundleMgrInterfaceCode code, MessageParcel &data,
    T &parcelableInfo)
{
    ACCOUNT_LOGE("not support interface!");
    return ERR_ACCOUNT_COMMON_INTERFACE_NOT_SUPPORT_ERROR;
}

template<typename T>
bool BundleManagerAdapterProxy::GetParcelableInfos(BundleMgrInterfaceCode code, MessageParcel &data,
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

template<typename T>
bool BundleManagerAdapterProxy::GetVectorFromParcelIntelligent(
    BundleMgrInterfaceCode code, MessageParcel &data, std::vector<T> &parcelableInfos)
{
    MessageParcel reply;
    if (!SendTransactCmd(code, data, reply)) {
        return false;
    }

    if (!reply.ReadBool()) {
        ACCOUNT_LOGE("readParcelableInfo failed");
        return false;
    }

    if (InnerGetVectorFromParcelIntelligent<T>(reply, parcelableInfos) != ERR_OK) {
        ACCOUNT_LOGE("InnerGetVectorFromParcelIntelligent failed");
        return false;
    }

    return true;
}

template<typename T>
ErrCode BundleManagerAdapterProxy::InnerGetVectorFromParcelIntelligent(
    MessageParcel &reply, std::vector<T> &parcelableInfos)
{
    size_t dataSize = static_cast<size_t>(reply.ReadInt32());
    if (dataSize == 0) {
        ACCOUNT_LOGW("Parcel no data");
        return ERR_OK;
    }

    void *buffer = nullptr;
    if (!SendData(buffer, dataSize, reply.ReadRawData(dataSize))) {
        ACCOUNT_LOGE("Fail to read raw data, length = %{public}zu", dataSize);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel tempParcel;
    if (!tempParcel.ParseFrom(reinterpret_cast<uintptr_t>(buffer), dataSize)) {
        ACCOUNT_LOGE("Fail to ParseFrom");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int32_t infoSize = tempParcel.ReadInt32();
    for (int32_t i = 0; i < infoSize; i++) {
        std::unique_ptr<T> info(tempParcel.ReadParcelable<T>());
        if (info == nullptr) {
            ACCOUNT_LOGE("Read Parcelable infos failed");
            return false;
        }
        parcelableInfos.emplace_back(*info);
    }

    return ERR_OK;
}

template <typename T>
bool BundleManagerAdapterProxy::ParseAshmem(
    int32_t infoSize, const char* dataStr, int32_t offset, std::vector<T> &parcelableInfos)
{
    if (dataStr == nullptr) {
        return false;
    }
    while (infoSize > 0) {
        std::string lenStr;
        if (!ParseStr(dataStr, ASHMEM_LEN, offset, lenStr)) {
            return false;
        }
        int32_t strLen = 0;
        if (!StrToInt(lenStr, strLen)) {
            ACCOUNT_LOGE("Convert lenStr failed");
            return false;
        }
        offset += ASHMEM_LEN;
        std::string infoStr;
        if (!ParseStr(dataStr, strLen, offset, infoStr)) {
            return false;
        }
        T info;
        if (!ParseInfo(infoStr, info)) {
            return false;
        }
        parcelableInfos.emplace_back(info);
        infoSize--;
        offset += strLen;
    }
    return true;
}

template <typename T>
bool BundleManagerAdapterProxy::GetParcelableInfosFromAshmem(
    BundleMgrInterfaceCode code, MessageParcel &data, std::vector<T> &parcelableInfos)
{
    MessageParcel reply;
    if (!SendTransactCmd(code, data, reply)) {
        return false;
    }
    if (!reply.ReadBool()) {
        return false;
    }
    int32_t infoSize = reply.ReadInt32();
    if (infoSize > MAX_INFO_SIZE) {
        ACCOUNT_LOGE("info size is too large");
        return false;
    }
    sptr<Ashmem> ashmem = reply.ReadAshmem();
    if (ashmem == nullptr) {
        ACCOUNT_LOGE("Ashmem is nullptr");
        return false;
    }
    if (!ashmem->MapReadOnlyAshmem()) {
        ACCOUNT_LOGE("Map read only ashmem fail");
        ClearAshmem(ashmem);
        return false;
    }
    int32_t offset = 0;
    const char* dataStr = static_cast<const char*>(
        ashmem->ReadFromAshmem(ashmem->GetAshmemSize(), offset));
    bool result = ParseAshmem(infoSize, dataStr, offset, parcelableInfos);
    ClearAshmem(ashmem);
    return result;
}

bool BundleManagerAdapterProxy::SendData(void *&buffer, size_t size, const void *data)
{
    if (data == nullptr) {
        ACCOUNT_LOGE("data is nullptr");
        return false;
    }

    if (size <= 0) {
        ACCOUNT_LOGE("size is invalid");
        return false;
    }

    buffer = malloc(size);
    if (buffer == nullptr) {
        ACCOUNT_LOGE("buffer malloc failed");
        return false;
    }

    if (memcpy_s(buffer, size, data, size) != EOK) {
        free(buffer);
        ACCOUNT_LOGE("memcpy_s failed");
        return false;
    }

    return true;
}

bool BundleManagerAdapterProxy::SendTransactCmd(
    BundleMgrInterfaceCode code, MessageParcel &data, MessageParcel &reply)
{
    MessageOption option(MessageOption::TF_SYNC);

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        ACCOUNT_LOGE("fail to send transact cmd %{public}d due to remote object", code);
        return false;
    }
    int32_t result = remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
    if (result != NO_ERROR) {
        ACCOUNT_LOGE("receive error transact code %{public}d in transact cmd %{public}d", result, code);
        return false;
    }
    return true;
}
}  // namespace AccountSA
}  // namespace OHOS
