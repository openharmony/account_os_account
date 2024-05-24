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
#include "os_account_proxy.h"
#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
namespace {
const size_t MAX_INFO_SIZE = 1024;
const uint32_t ACCOUNT_MAX_SIZE = 1000;
}

OsAccountProxy::OsAccountProxy(const sptr<IRemoteObject> &object) : IRemoteProxy<IOsAccount>(object)
{}

OsAccountProxy::~OsAccountProxy()
{}

ErrCode OsAccountProxy::CreateOsAccount(
    const std::string &name, const OsAccountType &type, OsAccountInfo &osAccountInfo)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteString(name)) {
        ACCOUNT_LOGE("failed to write os account name");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    if (!data.WriteInt32(static_cast<int32_t>(type))) {
        ACCOUNT_LOGE("failed to write os account type");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    ErrCode result = SendRequest(OsAccountInterfaceCode::CREATE_OS_ACCOUNT, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return result;
    }

    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for create os account.");
        return result;
    }
    std::shared_ptr<OsAccountInfo> infoPtr(reply.ReadParcelable<OsAccountInfo>());
    if (infoPtr == nullptr) {
        ACCOUNT_LOGE("failed to read OsAccountInfo");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    osAccountInfo = *infoPtr;
    return ERR_OK;
}

ErrCode OsAccountProxy::CreateOsAccount(const std::string &localName, const std::string &shortName,
    const OsAccountType &type, OsAccountInfo &osAccountInfo, const CreateOsAccountOptions &options)
{
    MessageParcel data;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteString(localName)) {
        ACCOUNT_LOGE("failed to write os account local name");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    if (!data.WriteString(shortName)) {
        ACCOUNT_LOGE("failed to write os account short name");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    if (!data.WriteInt32(static_cast<int32_t>(type))) {
        ACCOUNT_LOGE("failed to write os account type");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    if (!data.WriteParcelable(&options)) {
        ACCOUNT_LOGE("failed to write options");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    MessageParcel reply;
    ErrCode result = SendRequest(OsAccountInterfaceCode::CREATE_OS_ACCOUNT_WITH_SHORT_NAME, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return result;
    }

    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for create os account.");
        return result;
    }
    std::shared_ptr<OsAccountInfo> infoPtr(reply.ReadParcelable<OsAccountInfo>());
    if (infoPtr == nullptr) {
        ACCOUNT_LOGE("failed to read OsAccountInfo");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    osAccountInfo = *infoPtr;
    return ERR_OK;
}

ErrCode OsAccountProxy::CreateOsAccountWithFullInfo(OsAccountInfo &osAccountInfo)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteParcelable(&osAccountInfo)) {
        ACCOUNT_LOGE("failed to write osAccountInfo info ");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    MessageParcel reply;
    ErrCode result = SendRequest(OsAccountInterfaceCode::CREATE_OS_ACCOUNT_WITH_FULL_INFO, data, reply);
    if (result != ERR_OK) {
        return result;
    }

    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for create os account with full user info, result %{public}d.", result);
        return result;
    }
    return ERR_OK;
}

ErrCode OsAccountProxy::UpdateOsAccountWithFullInfo(OsAccountInfo &osAccountInfo)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteParcelable(&osAccountInfo)) {
        ACCOUNT_LOGE("failed to write osAccountInfo info ");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    MessageParcel reply;
    ErrCode result = SendRequest(OsAccountInterfaceCode::UPDATE_OS_ACCOUNT_WITH_FULL_INFO, data, reply);
    if (result != ERR_OK) {
        return result;
    }

    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for update os account with full user info, result %{public}d.", result);
        return result;
    }
    return ERR_OK;
}

ErrCode OsAccountProxy::CreateOsAccountForDomain(const OsAccountType &type, const DomainAccountInfo &domainInfo,
    const sptr<IDomainAccountCallback> &callback, const CreateOsAccountForDomainOptions& options)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("Failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteInt32(static_cast<int32_t>(type))) {
        ACCOUNT_LOGE("Failed to write type ");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    if (!data.WriteParcelable(&domainInfo)) {
        ACCOUNT_LOGE("Fail to write domainInfo");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    if ((callback == nullptr) || (!data.WriteRemoteObject(callback->AsObject()))) {
        ACCOUNT_LOGE("Fail to write callback");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    if (!data.WriteParcelable(&options)) {
        ACCOUNT_LOGE("Failed to write options");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    ErrCode result = SendRequest(OsAccountInterfaceCode::CREATE_OS_ACCOUNT_FOR_DOMAIN, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Failed to send request, result %{public}d.", result);
        return result;
    }

    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Failed to read reply for create os account for domain, result %{public}d.", result);
        return result;
    }
    return ERR_OK;
}

ErrCode OsAccountProxy::RemoveOsAccount(const int id)
{
    MessageParcel reply;
    return SendRequestWithAccountId(OsAccountInterfaceCode::REMOVE_OS_ACCOUNT, reply, id);
}

ErrCode OsAccountProxy::IsOsAccountExists(const int id, bool &isOsAccountExists)
{
    MessageParcel reply;
    ErrCode result = SendRequestWithAccountId(OsAccountInterfaceCode::IS_OS_ACCOUNT_EXISTS, reply, id);
    if (result == ERR_OK) {
        isOsAccountExists = reply.ReadBool();
    }
    return result;
}

ErrCode OsAccountProxy::IsOsAccountActived(const int id, bool &isOsAccountActived)
{
    MessageParcel reply;
    ErrCode result = SendRequestWithAccountId(OsAccountInterfaceCode::IS_OS_ACCOUNT_ACTIVED, reply, id);
    if (result == ERR_OK) {
        isOsAccountActived = reply.ReadBool();
    }
    return result;
}

ErrCode OsAccountProxy::CheckOsAccountConstraintEnabled(
    OsAccountInterfaceCode code, const int id, const std::string &constraint, bool &isEnabled)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteInt32(id)) {
        ACCOUNT_LOGE("failed to write int for id");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteString(constraint)) {
        ACCOUNT_LOGE("failed to write string for constraint");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    MessageParcel reply;
    ErrCode ret = SendRequest(code, data, reply);
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", ret);
        return ret;
    }
    if (!reply.ReadInt32(ret)) {
        ACCOUNT_LOGE("failed to read result for check os account constraint enable.");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    if (ret != ERR_OK) {
        ACCOUNT_LOGE("failed to check os account constraint enabled, result %{public}d.", ret);
        return ret;
    }
    if (!reply.ReadBool(isEnabled)) {
        ACCOUNT_LOGE("failed to read result for check os account constraint enable.");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode OsAccountProxy::IsOsAccountConstraintEnable(
    const int id, const std::string &constraint, bool &isConstraintEnable)
{
    return CheckOsAccountConstraintEnabled(
        OsAccountInterfaceCode::IS_OS_ACCOUNT_CONSTRAINT_ENABLE, id, constraint, isConstraintEnable);
}

ErrCode OsAccountProxy::CheckOsAccountConstraintEnabled(
    const int id, const std::string &constraint, bool &isEnabled)
{
    return CheckOsAccountConstraintEnabled(
        OsAccountInterfaceCode::CHECK_OS_ACCOUNT_CONSTRAINT_ENABLED, id, constraint, isEnabled);
}

ErrCode OsAccountProxy::IsOsAccountVerified(const int id, bool &isVerified)
{
    MessageParcel reply;
    ErrCode result = SendRequestWithAccountId(OsAccountInterfaceCode::IS_OS_ACCOUNT_VERIFIED, reply, id);
    if (result == ERR_OK) {
        isVerified = reply.ReadBool();
    }
    return result;
}

ErrCode OsAccountProxy::GetCreatedOsAccountsCount(unsigned int &osAccountsCount)
{
    osAccountsCount = 0;
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    ErrCode result = SendRequest(OsAccountInterfaceCode::GET_CREATED_OS_ACCOUNT_COUNT, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return result;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for get os account count, result %{public}d.", result);
        return result;
    }
    osAccountsCount = reply.ReadUint32();

    return ERR_OK;
}

ErrCode OsAccountProxy::GetOsAccountLocalIdFromProcess(int &id)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    ErrCode result = SendRequest(OsAccountInterfaceCode::GET_OS_ACCOUNT_LOCAL_ID_FROM_PROCESS, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return result;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for get os account id from process, result %{public}d.", result);
        return result;
    }
    id = reply.ReadInt32();

    return ERR_OK;
}

ErrCode OsAccountProxy::IsMainOsAccount(bool &isMainOsAccount)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    ErrCode result = SendRequest(OsAccountInterfaceCode::IS_MAIN_OS_ACCOUNT, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return result;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for is main os account, result %{public}d.", result);
        return result;
    }
    isMainOsAccount = reply.ReadBool();

    return ERR_OK;
}

ErrCode OsAccountProxy::GetOsAccountLocalIdFromDomain(const DomainAccountInfo &domainInfo, int &id)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteString(domainInfo.domain_)) {
        ACCOUNT_LOGE("failed to write int for domain.");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteString(domainInfo.accountName_)) {
        ACCOUNT_LOGE("failed to write int for domain account name.");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    ErrCode result = SendRequest(OsAccountInterfaceCode::GET_OS_ACCOUNT_LOCAL_ID_FROM_DOMAIN, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return result;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("read from reply err, result %{public}d.", result);
        return result;
    }
    id = reply.ReadInt32();

    return ERR_OK;
}

ErrCode OsAccountProxy::QueryMaxOsAccountNumber(uint32_t &maxOsAccountNumber)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    ErrCode result = SendRequest(OsAccountInterfaceCode::QUERY_MAX_OS_ACCOUNT_NUMBER, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return result;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for query os account number, result %{public}d.", result);
        return result;
    }
    maxOsAccountNumber = static_cast<uint32_t>(reply.ReadInt32());

    return ERR_OK;
}

ErrCode OsAccountProxy::QueryMaxLoggedInOsAccountNumber(uint32_t &maxNum)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("Failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    MessageParcel reply;
    ErrCode result = SendRequest(OsAccountInterfaceCode::QUERY_MAX_LOGGED_IN_OS_ACCOUNT_NUMBER, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return result;
    }
    if (!reply.ReadInt32(result)) {
        ACCOUNT_LOGE("Failed to read errCode");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    if (result != ERR_OK) {
        return result;
    }
    if (!reply.ReadUint32(maxNum)) {
        ACCOUNT_LOGE("Failed to read maxNum");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode OsAccountProxy::GetOsAccountAllConstraints(const int id, std::vector<std::string> &constraints)
{
    MessageParcel reply;
    ErrCode result = SendRequestWithAccountId(OsAccountInterfaceCode::GET_OS_ACCOUNT_ALL_CONSTRAINTS, reply, id);
    if (result != ERR_OK) {
        return result;
    }
    bool readFlag = reply.ReadStringVector(&constraints);
    if (!readFlag) {
        ACCOUNT_LOGE("ReadStringVector failed, result %{public}d.", result);
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode OsAccountProxy::QueryAllCreatedOsAccounts(std::vector<OsAccountInfo> &osAccountInfos)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    ErrCode result = SendRequest(OsAccountInterfaceCode::QUERY_ALL_CREATED_OS_ACCOUNTS, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return result;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for query all os accounts, result %{public}d.", result);
        return result;
    }
    ReadOsAccountInfoList(reply, osAccountInfos);

    return ERR_OK;
}

ErrCode OsAccountProxy::QueryCurrentOsAccount(OsAccountInfo &osAccountInfo)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    ErrCode result = SendRequest(OsAccountInterfaceCode::QUERY_CURRENT_OS_ACCOUNT, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return result;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for query current os account, result %{public}d.", result);
        return result;
    }
    std::shared_ptr<OsAccountInfo> infoPtr(reply.ReadParcelable<OsAccountInfo>());
    if (infoPtr == nullptr) {
        ACCOUNT_LOGE("failed to read OsAccountInfo");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    osAccountInfo = *infoPtr;
    return ERR_OK;
}

ErrCode OsAccountProxy::QueryOsAccountById(const int id, OsAccountInfo &osAccountInfo)
{
    MessageParcel reply;
    ErrCode result = SendRequestWithAccountId(OsAccountInterfaceCode::QUERY_OS_ACCOUNT_BY_ID, reply, id);
    if (result != ERR_OK) {
        return result;
    }
    std::shared_ptr<OsAccountInfo> infoPtr(reply.ReadParcelable<OsAccountInfo>());
    if (infoPtr == nullptr) {
        ACCOUNT_LOGE("failed to read OsAccountInfo");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    osAccountInfo = *infoPtr;
    return ERR_OK;
}

ErrCode OsAccountProxy::GetOsAccountTypeFromProcess(OsAccountType &type)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    ErrCode result = SendRequest(OsAccountInterfaceCode::GET_OS_ACCOUNT_TYPE_FROM_PROCESS, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return result;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for get os account type by process, result %{public}d.", result);
        return result;
    }
    type = static_cast<OsAccountType>(reply.ReadInt32());

    return ERR_OK;
}

ErrCode OsAccountProxy::GetOsAccountType(const int id, OsAccountType& type)
{
    MessageParcel reply;
    ErrCode result = SendRequestWithAccountId(OsAccountInterfaceCode::GET_OS_ACCOUNT_TYPE, reply, id);
    if (result != ERR_OK) {
        return result;
    }

    int32_t typeResult = 0;
    if (!reply.ReadInt32(typeResult)) {
        ACCOUNT_LOGE("Failed to read type.");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    type = static_cast<OsAccountType>(typeResult);

    return ERR_OK;
}

ErrCode OsAccountProxy::GetOsAccountProfilePhoto(const int id, std::string &photo)
{
    MessageParcel reply;
    ErrCode result = SendRequestWithAccountId(OsAccountInterfaceCode::GET_OS_ACCOUNT_PROFILE_PHOTO, reply, id);
    if (result != ERR_OK) {
        return result;
    }
    photo = reply.ReadString();

    return ERR_OK;
}

ErrCode OsAccountProxy::IsMultiOsAccountEnable(bool &isMultiOsAccountEnable)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    ErrCode result = SendRequest(OsAccountInterfaceCode::IS_MULTI_OS_ACCOUNT_ENABLE, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return result;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for is multi os account enable.");
        return result;
    }
    isMultiOsAccountEnable = reply.ReadBool();

    return ERR_OK;
}

ErrCode OsAccountProxy::SetOsAccountName(const int id, const std::string &name)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }
    if (!data.WriteInt32(id)) {
        ACCOUNT_LOGE("failed to write int for id %{public}d.", id);
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteString(name)) {
        ACCOUNT_LOGE("failed to write string for name");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    MessageParcel reply;
    ErrCode result = SendRequest(OsAccountInterfaceCode::SET_OS_ACCOUNT_NAME, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return result;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for set os account name, result %{public}d.", result);
        return result;
    }

    return ERR_OK;
}

ErrCode OsAccountProxy::SetOsAccountConstraints(
    const int id, const std::vector<std::string> &constraints, const bool enable)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }
    if (!data.WriteInt32(id)) {
        ACCOUNT_LOGE("failed to write id for setting constraints");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteStringVector(constraints)) {
        ACCOUNT_LOGE("failed to write stringVector for constraints");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteBool(enable)) {
        ACCOUNT_LOGE("failed to write bool for enable");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    MessageParcel reply;
    ErrCode result = SendRequest(OsAccountInterfaceCode::SET_OS_ACCOUNT_CONSTRAINTS, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return result;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for set os account constraints, result %{public}d.", result);
        return result;
    }

    return ERR_OK;
}

ErrCode OsAccountProxy::SetOsAccountProfilePhoto(const int id, const std::string &photo)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }
    if (!data.WriteInt32(id)) {
        ACCOUNT_LOGE("failed to write id for setting photo");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteString(photo)) {
        ACCOUNT_LOGE("failed to write string for photo");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    MessageParcel reply;
    ErrCode result = SendRequest(OsAccountInterfaceCode::SET_OS_ACCOUNT_PROFILE_PHOTO, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return result;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for set os account profile photo, result %{public}d.", result);
        return result;
    }

    return ERR_OK;
}

ErrCode OsAccountProxy::ActivateOsAccount(const int id)
{
    MessageParcel reply;
    return SendRequestWithAccountId(OsAccountInterfaceCode::ACTIVATE_OS_ACCOUNT, reply, id);
}

ErrCode OsAccountProxy::DeactivateOsAccount(const int id)
{
    MessageParcel reply;
    return SendRequestWithAccountId(OsAccountInterfaceCode::DEACTIVATE_OS_ACCOUNT, reply, id);
}

ErrCode OsAccountProxy::DeactivateAllOsAccounts()
{
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("Write descriptor failed.");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }
    ErrCode result = SendRequest(OsAccountInterfaceCode::DEACTIVATE_ALL_OS_ACCOUNTS, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest failed, result=%{public}d.", result);
        return result;
    }

    if (!reply.ReadInt32(result)) {
        ACCOUNT_LOGE("Read result failed.");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Deactivate all os account failed, result=%{public}d.", result);
    }
    return result;
}

ErrCode OsAccountProxy::StartOsAccount(const int id)
{
    MessageParcel reply;
    return SendRequestWithAccountId(OsAccountInterfaceCode::START_OS_ACCOUNT, reply, id);
}

ErrCode OsAccountProxy::GetOsAccountLocalIdBySerialNumber(const int64_t serialNumber, int &id)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteInt64(serialNumber)) {
        ACCOUNT_LOGE("failed to write int for serialNumber");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    ErrCode result = SendRequest(OsAccountInterfaceCode::GET_OS_ACCOUNT_LOCAL_ID_FOR_SERIAL_NUMBER, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return result;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for get os account id by serial number, result %{public}d.", result);
        return result;
    }
    id = reply.ReadInt32();

    return ERR_OK;
}

ErrCode OsAccountProxy::GetSerialNumberByOsAccountLocalId(const int &id, int64_t &serialNumber)
{
    MessageParcel reply;
    ErrCode result = SendRequestWithAccountId(OsAccountInterfaceCode::GET_SERIAL_NUMBER_FOR_OS_ACCOUNT, reply, id);
    if (result == ERR_OK) {
        serialNumber = reply.ReadInt64();
    }
    return result;
}

ErrCode OsAccountProxy::SubscribeOsAccount(
    const OsAccountSubscribeInfo &subscribeInfo, const sptr<IRemoteObject> &eventListener)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteParcelable(&subscribeInfo)) {
        ACCOUNT_LOGE("failed to write parcelable for subscribeInfo");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    if (!data.WriteRemoteObject(eventListener)) {
        ACCOUNT_LOGE("failed to write remote object for eventListener");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    ErrCode result = SendRequest(OsAccountInterfaceCode::SUBSCRIBE_OS_ACCOUNT, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return result;
    }

    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for subscriber os account, result %{public}d.", result);
        return result;
    }

    return ERR_OK;
}

ErrCode OsAccountProxy::UnsubscribeOsAccount(const sptr<IRemoteObject> &eventListener)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteRemoteObject(eventListener)) {
        ACCOUNT_LOGE("failed to write remote object for eventListener");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    ErrCode result = SendRequest(OsAccountInterfaceCode::UNSUBSCRIBE_OS_ACCOUNT, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return result;
    }

    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for unsubscribe os account.");
    }

    return result;
}
OS_ACCOUNT_SWITCH_MOD OsAccountProxy::GetOsAccountSwitchMod()
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return OS_ACCOUNT_SWITCH_MOD::ERROR_MOD;
    }

    ErrCode result = SendRequest(OsAccountInterfaceCode::GET_OS_ACCOUNT_SWITCH_MOD, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return OS_ACCOUNT_SWITCH_MOD::ERROR_MOD;
    }

    OS_ACCOUNT_SWITCH_MOD osAccountSwitchMod = static_cast<OS_ACCOUNT_SWITCH_MOD>(reply.ReadInt32());

    return osAccountSwitchMod;
}

ErrCode OsAccountProxy::SendRequestWithAccountId(OsAccountInterfaceCode code, MessageParcel &reply, int id)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteInt32(id)) {
        ACCOUNT_LOGE("failed to write int for id");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    ErrCode result = SendRequest(code, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return result;
    }
    if (!reply.ReadInt32(result)) {
        ACCOUNT_LOGE("failed to read result for Message code %{public}d.", code);
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for code %{public}d, result %{public}d.", code, result);
    }
    return result;
}

ErrCode OsAccountProxy::SendRequest(OsAccountInterfaceCode code, MessageParcel &data, MessageParcel &reply)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        ACCOUNT_LOGE("remote is nullptr, code = %{public}d", code);
        return ERR_ACCOUNT_COMMON_NULL_PTR_ERROR;
    }

    MessageOption option(MessageOption::TF_SYNC);
    int32_t result = remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to send os account request, code = %{public}d, result = %{public}d", code, result);
    }
    return result;
}

ErrCode OsAccountProxy::IsCurrentOsAccountVerified(bool &isVerified)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    ErrCode result = SendRequest(OsAccountInterfaceCode::IS_CURRENT_OS_ACCOUNT_VERIFIED, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return result;
    }

    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for is current os account verified, result %{public}d.", result);
        return result;
    }
    isVerified = reply.ReadBool();

    return ERR_OK;
}

ErrCode OsAccountProxy::IsOsAccountCompleted(const int id, bool &isOsAccountCompleted)
{
    MessageParcel reply;
    ErrCode result = SendRequestWithAccountId(OsAccountInterfaceCode::IS_OS_ACCOUNT_COMPLETED, reply, id);
    if (result != ERR_OK) {
        return result;
    }
    if (!reply.ReadBool(isOsAccountCompleted)) {
        ACCOUNT_LOGE("failed to read isOsAccountCompleted");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode OsAccountProxy::SetCurrentOsAccountIsVerified(const bool isVerified)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteBool(isVerified)) {
        ACCOUNT_LOGE("failed to write bool for isVerified");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    ErrCode result = SendRequest(OsAccountInterfaceCode::SET_CURRENT_OS_ACCOUNT_IS_VERIFIED, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return result;
    }

    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for set current os account verified, result %{public}d.", result);
        return result;
    }
    return ERR_OK;
}

ErrCode OsAccountProxy::SetOsAccountIsVerified(const int id, const bool isVerified)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }
    if (!data.WriteInt32(id)) {
        ACCOUNT_LOGE("failed to write id for setting verified status");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteBool(isVerified)) {
        ACCOUNT_LOGE("failed to write bool for isVerified");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    MessageParcel reply;
    ErrCode result = SendRequest(OsAccountInterfaceCode::SET_OS_ACCOUNT_IS_VERIFIED, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return result;
    }

    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for set os account verified, result %{public}d.", result);
        return result;
    }
    return ERR_OK;
}

ErrCode OsAccountProxy::DumpState(const int &id, std::vector<std::string> &state)
{
    MessageParcel reply;
    ErrCode result = SendRequestWithAccountId(OsAccountInterfaceCode::DUMP_STATE, reply, id);
    if (result != ERR_OK) {
        return result;
    }

    uint32_t size = reply.ReadUint32();
    for (uint32_t i = 0; i < size; i++) {
        std::string info = reply.ReadString();
        state.emplace_back(info);
    }
    return ERR_OK;
}

void OsAccountProxy::CreateBasicAccounts()
{
    ACCOUNT_LOGI("Do nothing.");
}

ErrCode OsAccountProxy::GetCreatedOsAccountNumFromDatabase(const std::string& storeID,
    int &createdOsAccountNum)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteString(storeID)) {
        ACCOUNT_LOGE("failed to write storeID for getting created os account");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    ErrCode result = SendRequest(OsAccountInterfaceCode::GET_CREATED_OS_ACCOUNT_NUM_FROM_DATABASE, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return result;
    }

    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply, result %{public}d.", result);
        return result;
    }
    createdOsAccountNum = reply.ReadInt32();
    return ERR_OK;
}

ErrCode OsAccountProxy::GetSerialNumberFromDatabase(const std::string& storeID, int64_t &serialNumber)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteString(storeID)) {
        ACCOUNT_LOGE("failed to write storeID for getting serial number from database");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    ErrCode result = SendRequest(OsAccountInterfaceCode::GET_SERIAL_NUM_FROM_DATABASE, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest failed, result %{public}d.", result);
        return result;
    }

    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply, result %{public}d.", result);
        return result;
    }
    serialNumber = reply.ReadInt64();
    return ERR_OK;
}

ErrCode OsAccountProxy::GetMaxAllowCreateIdFromDatabase(const std::string& storeID, int &id)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteString(storeID)) {
        ACCOUNT_LOGE("failed to write string for isVerified");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    ErrCode result = SendRequest(OsAccountInterfaceCode::GET_MAX_ALLOW_CREATE_ID_FROM_DATABASE, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest failed, result %{public}d.", result);
        return result;
    }

    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply, result %{public}d.", result);
        return result;
    }
    id = reply.ReadInt32();
    return ERR_OK;
}

ErrCode OsAccountProxy::GetOsAccountFromDatabase(const std::string& storeID,
    const int id, OsAccountInfo &osAccountInfo)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteString(storeID)) {
        ACCOUNT_LOGE("failed to write storeID for getting os account form database");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteInt32(id)) {
        ACCOUNT_LOGE("failed to write int for id");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    ErrCode result = SendRequest(OsAccountInterfaceCode::GET_OS_ACCOUNT_FROM_DATABASE, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest failed, result %{public}d.", result);
        return result;
    }

    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply, result %{public}d.", result);
        return result;
    }
    std::shared_ptr<OsAccountInfo> infoPtr(reply.ReadParcelable<OsAccountInfo>());
    if (infoPtr == nullptr) {
        ACCOUNT_LOGE("failed to read OsAccountInfo");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    osAccountInfo = *infoPtr;
    return ERR_OK;
}

ErrCode OsAccountProxy::GetOsAccountListFromDatabase(const std::string& storeID,
    std::vector<OsAccountInfo> &osAccountList)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    if (!data.WriteString(storeID)) {
        ACCOUNT_LOGE("failed to write storeID for getting os account list from database");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    ErrCode result = SendRequest(OsAccountInterfaceCode::GET_OS_ACCOUNT_LIST_FROM_DATABASE, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest failed, result %{public}d.", result);
        return result;
    }

    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply, result %{public}d.", result);
        return result;
    }
    ReadOsAccountInfoList(reply, osAccountList);
    return ERR_OK;
}

ErrCode OsAccountProxy::QueryActiveOsAccountIds(std::vector<int32_t>& ids)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    ErrCode result = SendRequest(OsAccountInterfaceCode::QUERY_ACTIVE_OS_ACCOUNT_IDS, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return result;
    }

    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for query active os account ids, result %{public}d.", result);
        return result;
    }

    bool readFlag = reply.ReadInt32Vector(&ids);
    if (!readFlag) {
        ACCOUNT_LOGE("failed to read vector for active ids.");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode OsAccountProxy::QueryOsAccountConstraintSourceTypes(const int32_t id,
    const std::string &constraint, std::vector<ConstraintSourceTypeInfo> &constraintSourceTypeInfos)
{
    constraintSourceTypeInfos.clear();
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }
    if (!data.WriteInt32(id)) {
        ACCOUNT_LOGE("failed to write id for setting constraint source types");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteString(constraint)) {
        ACCOUNT_LOGE("failed to write string for constraint");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    MessageParcel reply;
    ErrCode result = SendRequest(OsAccountInterfaceCode::QUERY_OS_ACCOUNT_CONSTRAINT_SOURCE_TYPES, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return result;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        return result;
    }
    uint32_t size = reply.ReadUint32();
    for (uint32_t i = 0; i < size; ++i) {
        ConstraintSourceTypeInfo constraintSrcInfo;
        constraintSrcInfo.localId = reply.ReadInt32();
        constraintSrcInfo.typeInfo = static_cast<ConstraintSourceType>(reply.ReadInt32());
        constraintSourceTypeInfos.push_back(constraintSrcInfo);
    }
    return ERR_OK;
}

ErrCode OsAccountProxy::SetGlobalOsAccountConstraints(const std::vector<std::string> &constraints,
    const bool enable, const int32_t enforcerId, const bool isDeviceOwner)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }
    if (!data.WriteStringVector(constraints)) {
        ACCOUNT_LOGE("failed to write stringVector for constraints");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    if (!data.WriteBool(enable)) {
        ACCOUNT_LOGE("failed to write bool for enable");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    if (!data.WriteInt32(enforcerId)) {
        ACCOUNT_LOGE("failed to write int for enforcerId");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    if (!data.WriteBool(isDeviceOwner)) {
        ACCOUNT_LOGE("failed to write bool for isDeviceOwner");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    ErrCode result = SendRequest(OsAccountInterfaceCode::SET_GLOBAL_OS_ACCOUNT_CONSTRAINTS, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return result;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for set global os account constraints.");
        return result;
    }
    return ERR_OK;
}

ErrCode OsAccountProxy::SetSpecificOsAccountConstraints(const std::vector<std::string> &constraints,
    const bool enable, const int32_t targetId, const int32_t enforcerId, const bool isDeviceOwner)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }
    if (!data.WriteStringVector(constraints)) {
        ACCOUNT_LOGE("failed to write stringVector for constraints");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    if (!data.WriteBool(enable)) {
        ACCOUNT_LOGE("failed to write bool for enable");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    if (!data.WriteInt32(targetId)) {
        ACCOUNT_LOGE("failed to write int for targetId");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    if (!data.WriteInt32(enforcerId)) {
        ACCOUNT_LOGE("failed to write int for enforcerId");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    if (!data.WriteBool(isDeviceOwner)) {
        ACCOUNT_LOGE("failed to write bool for isDeviceOwner");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    ErrCode result = SendRequest(OsAccountInterfaceCode::SET_SPECIFIC_OS_ACCOUNT_CONSTRAINTS, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return result;
    }
    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for set specific os account constraints.");
        return result;
    }
    return ERR_OK;
}

ErrCode OsAccountProxy::SetDefaultActivatedOsAccount(const int32_t id)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteInt32(id)) {
        ACCOUNT_LOGE("failed to write id for setting default activated os account");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    MessageParcel reply;
    ErrCode result = SendRequest(OsAccountInterfaceCode::SET_DEFAULT_ACTIVATED_OS_ACCOUNT, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return result;
    }
    if (!reply.ReadInt32(result)) {
        ACCOUNT_LOGE("failed to read result for set default activated os account.");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    return result;
}

ErrCode OsAccountProxy::GetDefaultActivatedOsAccount(int32_t &id)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    MessageParcel reply;
    ErrCode result = SendRequest(OsAccountInterfaceCode::GET_DEFAULT_ACTIVATED_OS_ACCOUNT, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return result;
    }
    if (!reply.ReadInt32(result)) {
        ACCOUNT_LOGE("failed to read result for get default activated os account.");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to get default activated os account, result %{public}d.", result);
        return result;
    }
    if (!reply.ReadInt32(id)) {
        ACCOUNT_LOGE("failed to read local id");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    return ERR_OK;
}

bool OsAccountProxy::ReadOsAccountInfoList(MessageParcel &data, std::vector<OsAccountInfo> &infoList)
{
    infoList.clear();
    uint32_t infoSize = 0;
    if (!data.ReadUint32(infoSize)) {
        ACCOUNT_LOGE("Account read Parcelable size failed.");
        return false;
    }
    if (infoSize > MAX_INFO_SIZE) {
        ACCOUNT_LOGE("the size of info list is too large");
        return false;
    }

    for (uint32_t index = 0; index < infoSize; index++) {
        std::shared_ptr<OsAccountInfo> info(data.ReadParcelable<OsAccountInfo>());
        if (info == nullptr) {
            ACCOUNT_LOGE("Account read Parcelable infos failed.");
            return false;
        }
        infoList.emplace_back(*info);
    }

    return true;
}

ErrCode OsAccountProxy::GetOsAccountShortName(std::string &shortName)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    MessageParcel reply;
    ErrCode result = SendRequest(OsAccountInterfaceCode::GET_OS_ACCOUNT_SHORT_NAME, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return result;
    }

    result = reply.ReadInt32();
    if (result != ERR_OK) {
        ACCOUNT_LOGE("failed to read reply for is current os account verified, result %{public}d.", result);
        return result;
    }
    if (!reply.ReadString(shortName)) {
        ACCOUNT_LOGE("failed to read short name");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }

    return ERR_OK;
}

ErrCode OsAccountProxy::GetOsAccountName(std::string &name)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("Failed to write descriptor!");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }

    MessageParcel reply;
    ErrCode result = SendRequest(OsAccountInterfaceCode::GET_OS_ACCOUNT_NAME, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest err, result %{public}d.", result);
        return result;
    }

    if (!reply.ReadInt32(result)) {
        ACCOUNT_LOGE("Read result from reply failed.");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Failed to read reply for is current os account verified, result=%{public}d.", result);
        return result;
    }
    if (!reply.ReadString(name)) {
        ACCOUNT_LOGE("Failed to read short name");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }

    return ERR_OK;
}

ErrCode OsAccountProxy::GetOsAccountShortNameById(const int32_t id, std::string &shortName)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("Write descriptor failed.");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }
    if (!data.WriteInt32(id)) {
        ACCOUNT_LOGE("Write id failed.");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }

    MessageParcel reply;
    ErrCode result = SendRequest(OsAccountInterfaceCode::GET_OS_ACCOUNT_SHORT_NAME_BY_ID, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest failed, result=%{public}d.", result);
        return result;
    }

    if (!reply.ReadInt32(result)) {
        ACCOUNT_LOGE("Read result from reply failed.");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Get os account short name failed, result=%{public}d.", result);
        return result;
    }
    if (!reply.ReadString(shortName)) {
        ACCOUNT_LOGE("Read short name failed.");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }

    return ERR_OK;
}

ErrCode OsAccountProxy::IsOsAccountForeground(const int32_t localId, const uint64_t displayId, bool &isForeground)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("Write descriptor failed.");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }
    if (!data.WriteInt32(localId)) {
        ACCOUNT_LOGE("Write localId failed.");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteUint64(displayId)) {
        ACCOUNT_LOGE("Write displayId failed.");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    MessageParcel reply;
    ErrCode result = SendRequest(OsAccountInterfaceCode::IS_OS_ACCOUNT_FOREGROUND, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest failed, result=%{public}d.", result);
        return result;
    }
    if (!reply.ReadInt32(result)) {
        ACCOUNT_LOGE("Read result failed.");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    if (result != ERR_OK) {
        ACCOUNT_LOGE("IsOsAccountForeground failed, result=%{public}d.", result);
        return result;
    }
    if (!reply.ReadBool(isForeground)) {
        ACCOUNT_LOGE("Read isForeground failed.");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode OsAccountProxy::GetForegroundOsAccountLocalId(const uint64_t displayId, int32_t &localId)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("Write descriptor failed.");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }
    if (!data.WriteUint64(displayId)) {
        ACCOUNT_LOGE("Write displayId failed.");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    MessageParcel reply;
    ErrCode result = SendRequest(OsAccountInterfaceCode::GET_FOREGROUND_OS_ACCOUNT_LOCAL_ID, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest failed, result=%{public}d.", result);
        return result;
    }
    if (!reply.ReadInt32(result)) {
        ACCOUNT_LOGE("Read result from reply failed.");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    if (result != ERR_OK) {
        ACCOUNT_LOGE("GetForegroundOsAccountLocalId failed, result=%{public}d.", result);
        return result;
    }
    if (!reply.ReadInt32(localId)) {
        ACCOUNT_LOGE("Read localId failed");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode OsAccountProxy::GetForegroundOsAccounts(std::vector<ForegroundOsAccount> &accounts)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("Write descriptor failed");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }
    MessageParcel reply;
    ErrCode result = SendRequest(OsAccountInterfaceCode::GET_FOREGROUND_OS_ACCOUNTS, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest failed, result=%{public}d.", result);
        return result;
    }
    if (!reply.ReadInt32(result)) {
        ACCOUNT_LOGE("Read result failed.");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    if (result != ERR_OK) {
        ACCOUNT_LOGE("GetForegroundOsAccounts failed, result=%{public}d.", result);
        return result;
    }
    uint32_t size = 0;
    if (!reply.ReadUint32(size)) {
        ACCOUNT_LOGE("Read foregroundAccounts size failed.");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    if (size >= ACCOUNT_MAX_SIZE) {
        ACCOUNT_LOGE("Account size exceeded.");
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    accounts.clear();
    for (uint32_t i = 0; i < size; ++i) {
        ForegroundOsAccount foregroundOsAccount;
        if (!reply.ReadInt32(foregroundOsAccount.localId) || !reply.ReadUint64(foregroundOsAccount.displayId)) {
            ACCOUNT_LOGE("Read ForegroundOsAccount failed.");
            return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
        }
        accounts.emplace_back(foregroundOsAccount);
    }
    return ERR_OK;
}

ErrCode OsAccountProxy::GetBackgroundOsAccountLocalIds(std::vector<int32_t> &localIds)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("Write descriptor failed.");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }
    MessageParcel reply;
    ErrCode result = SendRequest(OsAccountInterfaceCode::GET_BACKGROUND_OS_ACCOUNT_LOCAL_IDS, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest failed, result=%{public}d.", result);
        return result;
    }
    if (!reply.ReadInt32(result)) {
        ACCOUNT_LOGE("Read result failed.");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    if (result != ERR_OK) {
        ACCOUNT_LOGE("GetBackgroundOsAccountLocalIds failed, result=%{public}d.", result);
        return result;
    }
    localIds.clear();
    if (!reply.ReadInt32Vector(&localIds)) {
        ACCOUNT_LOGE("Read localIds failed.");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode OsAccountProxy::SetOsAccountToBeRemoved(int32_t localId, bool toBeRemoved)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        ACCOUNT_LOGE("Write descriptor failed.");
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }
    if (!data.WriteInt32(localId)) {
        ACCOUNT_LOGE("Write localId failed.");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteBool(toBeRemoved)) {
        ACCOUNT_LOGE("Write toBeRemoved failed.");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    MessageParcel reply;
    ErrCode result = SendRequest(OsAccountInterfaceCode::SET_OS_ACCOUNT_TO_BE_REMOVED, data, reply);
    if (result != ERR_OK) {
        ACCOUNT_LOGE("SendRequest failed, result=%{public}d.", result);
        return result;
    }
    if (!reply.ReadInt32(result)) {
        ACCOUNT_LOGE("Read result failed.");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    return result;
}
}  // namespace AccountSA
}  // namespace OHOS
