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
#include "os_account_stub.h"
#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
const std::map<uint32_t, OsAccountStub::MessageProcFunction> OsAccountStub::messageProcMap_ = {
    {
        static_cast<uint32_t>(IOsAccount::Message::CREATE_OS_ACCOUNT),
        &OsAccountStub::ProcCreateOsAccount,
    },
    {
        static_cast<uint32_t>(IOsAccount::Message::CREATE_OS_ACCOUNT_FOR_DOMAIN),
        &OsAccountStub::ProcCreateOsAccountForDomain,
    },
    {
        static_cast<uint32_t>(IOsAccount::Message::REMOVE_OS_ACCOUNT),
        &OsAccountStub::ProcRemoveOsAccount,
    },
    {
        static_cast<uint32_t>(IOsAccount::Message::IS_OS_ACCOUNT_EXISTS),
        &OsAccountStub::ProcIsOsAccountExists,
    },
    {
        static_cast<uint32_t>(IOsAccount::Message::IS_OS_ACCOUNT_ACTIVED),
        &OsAccountStub::ProcIsOsAccountActived,
    },
    {
        static_cast<uint32_t>(IOsAccount::Message::IS_OS_ACCOUNT_CONSTRAINT_ENABLE),
        &OsAccountStub::ProcIsOsAccountConstraintEnable,
    },
    {
        static_cast<uint32_t>(IOsAccount::Message::CHECK_OS_ACCOUNT_CONSTRAINT_ENABLED),
        &OsAccountStub::ProcCheckOsAccountConstraintEnabled,
    },
    {
        static_cast<uint32_t>(IOsAccount::Message::IS_OS_ACCOUNT_VERIFIED),
        &OsAccountStub::ProcIsOsAccountVerified,
    },
    {
        static_cast<uint32_t>(IOsAccount::Message::GET_CREATED_OS_ACCOUNT_COUNT),
        &OsAccountStub::ProcGetCreatedOsAccountsCount,
    },
    {
        static_cast<uint32_t>(IOsAccount::Message::GET_OS_ACCOUNT_LOCAL_ID_FROM_PROCESS),
        &OsAccountStub::ProcGetOsAccountLocalIdFromProcess,
    },
    {
        static_cast<uint32_t>(IOsAccount::Message::IS_MAIN_OS_ACCOUNT),
        &OsAccountStub::ProcIsMainOsAccount,
    },
    {
        static_cast<uint32_t>(IOsAccount::Message::GET_OS_ACCOUNT_LOCAL_ID_FROM_DOMAIN),
        &OsAccountStub::ProcGetOsAccountLocalIdFromDomain,
    },
    {
        static_cast<uint32_t>(IOsAccount::Message::QUERY_MAX_OS_ACCOUNT_NUMBER),
        &OsAccountStub::ProcQueryMaxOsAccountNumber,
    },
    {
        static_cast<uint32_t>(IOsAccount::Message::GET_OS_ACCOUNT_ALL_CONSTRAINTS),
        &OsAccountStub::ProcGetOsAccountAllConstraints,
    },
    {
        static_cast<uint32_t>(IOsAccount::Message::QUERY_ALL_CREATED_OS_ACCOUNTS),
        &OsAccountStub::ProcQueryAllCreatedOsAccounts,
    },
    {
        static_cast<uint32_t>(IOsAccount::Message::QUERY_CURRENT_OS_ACCOUNT),
        &OsAccountStub::ProcQueryCurrentOsAccount,
    },
    {
        static_cast<uint32_t>(IOsAccount::Message::QUERY_OS_ACCOUNT_BY_ID),
        &OsAccountStub::ProcQueryOsAccountById,
    },
    {
        static_cast<uint32_t>(IOsAccount::Message::GET_OS_ACCOUNT_TYPE_FROM_PROCESS),
        &OsAccountStub::ProcGetOsAccountTypeFromProcess,
    },
    {
        static_cast<uint32_t>(IOsAccount::Message::GET_OS_ACCOUNT_PROFILE_PHOTO),
        &OsAccountStub::ProcGetOsAccountProfilePhoto,
    },
    {
        static_cast<uint32_t>(IOsAccount::Message::IS_MULTI_OS_ACCOUNT_ENABLE),
        &OsAccountStub::ProcIsMultiOsAccountEnable,
    },
    {
        static_cast<uint32_t>(IOsAccount::Message::SET_OS_ACCOUNT_NAME),
        &OsAccountStub::ProcSetOsAccountName,
    },
    {
        static_cast<uint32_t>(IOsAccount::Message::SET_OS_ACCOUNT_CONSTRAINTS),
        &OsAccountStub::ProcSetOsAccountConstraints,
    },
    {
        static_cast<uint32_t>(IOsAccount::Message::SET_OS_ACCOUNT_PROFILE_PHOTO),
        &OsAccountStub::ProcSetOsAccountProfilePhoto,
    },
    {
        static_cast<uint32_t>(IOsAccount::Message::ACTIVATE_OS_ACCOUNT),
        &OsAccountStub::ProcActivateOsAccount,
    },
    {
        static_cast<uint32_t>(IOsAccount::Message::START_OS_ACCOUNT),
        &OsAccountStub::ProcStartOsAccount,
    },
    {
        static_cast<uint32_t>(IOsAccount::Message::STOP_OS_ACCOUNT),
        &OsAccountStub::ProcStopOsAccount,
    },
    {
        static_cast<uint32_t>(IOsAccount::Message::SUBSCRIBE_ACCOUNT),
        &OsAccountStub::ProcSubscribeOsAccount,
    },
    {
        static_cast<uint32_t>(IOsAccount::Message::UNSUBSCRIBE_ACCOUNT),
        &OsAccountStub::ProcUnsubscribeOsAccount,
    },
    {
        static_cast<uint32_t>(IOsAccount::Message::GET_OS_ACCOUNT_LOCAL_ID_FOR_SERIAL_NUMBER),
        &OsAccountStub::ProcGetOsAccountLocalIdBySerialNumber,
    },
    {
        static_cast<uint32_t>(IOsAccount::Message::GET_SERIAL_NUMBER_FOR_OS_ACCOUNT),
        &OsAccountStub::ProcGetSerialNumberByOsAccountLocalId,
    },
    {
        static_cast<uint32_t>(IOsAccount::Message::GET_OS_ACCOUNT_SWITCH_MOD),
        &OsAccountStub::ProcGetOsAccountSwitchMod,
    },
    {
        static_cast<uint32_t>(IOsAccount::Message::IS_CURRENT_OS_ACCOUNT_VERIFIED),
        &OsAccountStub::ProcIsCurrentOsAccountVerified,
    },
    {
        static_cast<uint32_t>(IOsAccount::Message::IS_OS_ACCOUNT_COMPLETED),
        &OsAccountStub::ProcIsOsAccountCompleted,
    },
    {
        static_cast<uint32_t>(IOsAccount::Message::SET_CURRENT_OS_ACCOUNT_IS_VERIFIED),
        &OsAccountStub::ProcSetCurrentOsAccountIsVerified,
    },
    {
        static_cast<uint32_t>(IOsAccount::Message::SET_OS_ACCOUNT_IS_VERIFIED),
        &OsAccountStub::ProcSetOsAccountIsVerified,
    },
    {
        static_cast<uint32_t>(IOsAccount::Message::DUMP_STATE),
        &OsAccountStub::ProcDumpState,
    },
    {
        static_cast<uint32_t>(IOsAccount::Message::GET_CREATED_OS_ACCOUNT_NUM_FROM_DATABASE),
        &OsAccountStub::ProcGetCreatedOsAccountNumFromDatabase,
    },
    {
        static_cast<uint32_t>(IOsAccount::Message::GET_SERIAL_NUM_FROM_DATABASE),
        &OsAccountStub::ProcGetSerialNumberFromDatabase,
    },
    {
        static_cast<uint32_t>(IOsAccount::Message::GET_MAX_ALLOW_CREATE_ID_FROM_DATABASE),
        &OsAccountStub::ProcGetMaxAllowCreateIdFromDatabase,
    },
    {
        static_cast<uint32_t>(IOsAccount::Message::GET_OS_ACCOUNT_FROM_DATABASE),
        &OsAccountStub::ProcGetOsAccountFromDatabase,
    },
    {
        static_cast<uint32_t>(IOsAccount::Message::GET_OS_ACCOUNT_LIST_FROM_DATABASE),
        &OsAccountStub::ProcGetOsAccountListFromDatabase,
    },
    {
        static_cast<uint32_t>(IOsAccount::Message::QUERY_ACTIVE_OS_ACCOUNT_IDS),
        &OsAccountStub::ProcQueryActiveOsAccountIds,
    },
    {
        static_cast<uint32_t>(IOsAccount::Message::QUERY_OS_ACCOUNT_CONSTRAINT_SOURCE_TYPES),
        &OsAccountStub::ProcQueryOsAccountConstraintSourceTypes,
    },
    {
        static_cast<uint32_t>(IOsAccount::Message::SET_GLOBAL_OS_ACCOUNT_CONSTRAINTS),
        &OsAccountStub::ProcSetGlobalOsAccountConstraints,
    },
    {
        static_cast<uint32_t>(IOsAccount::Message::SET_SPECIFIC_OS_ACCOUNT_CONSTRAINTS),
        &OsAccountStub::ProcSetSpecificOsAccountConstraints,
    },
};

OsAccountStub::OsAccountStub()
{}

OsAccountStub::~OsAccountStub()
{}

int OsAccountStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        ACCOUNT_LOGE("check descriptor failed! code %{public}u.", code);
        return ERR_ACCOUNT_COMMON_CHECK_DESCRIPTOR_ERROR;
    }

    auto messageProc = messageProcMap_.find(code);
    if (messageProc != messageProcMap_.end()) {
        auto messageProcFunction = messageProc->second;
        if (messageProcFunction != nullptr) {
            return (this->*messageProcFunction)(data, reply);
        }
    }
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

template<typename T>
bool OsAccountStub::WriteParcelableVector(const std::vector<T> &parcelableVector, MessageParcel &data)
{
    if (!data.WriteUint32(parcelableVector.size())) {
        ACCOUNT_LOGE("Account write ParcelableVector size failed");
        return false;
    }

    for (auto parcelable : parcelableVector) {
        if (!data.WriteParcelable(&parcelable)) {
            ACCOUNT_LOGE("Account write ParcelableVector Parcelable failed");
            return false;
        }
    }
    return true;
}

template<typename T>
bool OsAccountStub::ReadParcelableVector(std::vector<T> &parcelableInfos, MessageParcel &data)
{
    uint32_t infoSize = 0;
    if (!data.ReadUint32(infoSize)) {
        ACCOUNT_LOGE("read Parcelable size failed.");
        return false;
    }

    parcelableInfos.clear();
    for (uint32_t index = 0; index < infoSize; index++) {
        std::shared_ptr<T> info(data.ReadParcelable<T>());
        if (info == nullptr) {
            ACCOUNT_LOGE("read Parcelable infos failed.");
            return false;
        }
        parcelableInfos.emplace_back(*info);
    }

    return true;
}

ErrCode OsAccountStub::ProcCreateOsAccount(MessageParcel &data, MessageParcel &reply)
{
    std::string name = data.ReadString();
    if (name.size() == 0) {
        ACCOUNT_LOGE("failed to read string for name");
        reply.WriteInt32(ERR_OSACCOUNT_KIT_READ_LOCALNAME_ERROR);
        return ERR_NONE;
    }
    OsAccountType type = static_cast<OsAccountType>(data.ReadInt32());
    OsAccountInfo osAccountInfo;
    ErrCode result = CreateOsAccount(name, type, osAccountInfo);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteParcelable(&osAccountInfo)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcCreateOsAccountForDomain(MessageParcel &data, MessageParcel &reply)
{
    OsAccountType type = static_cast<OsAccountType>(data.ReadInt32());
    std::string domain = data.ReadString();
    std::string domainAccountName = data.ReadString();

    if (domain.empty() || domain.size() > Constants::DOMAIN_NAME_MAX_SIZE) {
        ACCOUNT_LOGE("read invalid domain length %{public}zu.", domain.size());
        reply.WriteInt32(ERR_OSACCOUNT_KIT_DOMAIN_NAME_LENGTH_INVALID_ERROR);
        return ERR_NONE;
    }

    if (domainAccountName.empty() || domainAccountName.size() > Constants::DOMAIN_ACCOUNT_NAME_MAX_SIZE) {
        ACCOUNT_LOGE("read invalid domain account name length %{public}zu.", domainAccountName.size());
        reply.WriteInt32(ERR_OSACCOUNT_KIT_DOMAIN_ACCOUNT_NAME_LENGTH_INVALID_ERROR);
        return ERR_NONE;
    }

    OsAccountInfo osAccountInfo;
    DomainAccountInfo domainInfo(domain, domainAccountName);
    ErrCode result = CreateOsAccountForDomain(type, domainInfo, osAccountInfo);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteParcelable(&osAccountInfo)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcRemoveOsAccount(MessageParcel &data, MessageParcel &reply)
{
    int32_t localId;
    if (!data.ReadInt32(localId)) {
        ACCOUNT_LOGE("failed to read localId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }

    ErrCode result = RemoveOsAccount(localId);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcSetOsAccountName(MessageParcel &data, MessageParcel &reply)
{
    int32_t localId;
    if (!data.ReadInt32(localId)) {
        ACCOUNT_LOGE("failed to read localId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    std::string localName = data.ReadString();
    ErrCode result = SetOsAccountName(localId, localName);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcSetOsAccountConstraints(MessageParcel &data, MessageParcel &reply)
{
    int32_t localId;
    if (!data.ReadInt32(localId)) {
        ACCOUNT_LOGE("failed to read localId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    std::vector<std::string> constraints;
    bool stringVectorReadSuccess = data.ReadStringVector(&constraints);
    if (!stringVectorReadSuccess) {
        ACCOUNT_LOGE("failed to read StringVector for constraints");
        return ERR_OSACCOUNT_KIT_READ_STRING_VECTOR_CONSTRAINTS_ERROR;
    }
    bool enable = data.ReadBool();
    ErrCode result = SetOsAccountConstraints(localId, constraints, enable);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcSetOsAccountProfilePhoto(MessageParcel &data, MessageParcel &reply)
{
    int32_t localId;
    if (!data.ReadInt32(localId)) {
        ACCOUNT_LOGE("failed to read localId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    std::string photo = data.ReadString();
    ErrCode result = SetOsAccountProfilePhoto(localId, photo);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcQueryOsAccountById(MessageParcel &data, MessageParcel &reply)
{
    int32_t localId;
    if (!data.ReadInt32(localId)) {
        ACCOUNT_LOGE("failed to read localId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    OsAccountInfo osAccountInfo = OsAccountInfo();
    ErrCode result = QueryOsAccountById(localId, osAccountInfo);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteParcelable(&osAccountInfo)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcQueryCurrentOsAccount(MessageParcel &data, MessageParcel &reply)
{
    OsAccountInfo osAccountInfo = OsAccountInfo();
    ErrCode result = QueryCurrentOsAccount(osAccountInfo);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteParcelable(&osAccountInfo)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcQueryAllCreatedOsAccounts(MessageParcel &data, MessageParcel &reply)
{
    std::vector<OsAccountInfo> osAccountInfos;
    osAccountInfos.clear();
    ErrCode result = QueryAllCreatedOsAccounts(osAccountInfos);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!WriteParcelableVector(osAccountInfos, reply)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcQueryMaxOsAccountNumber(MessageParcel &data, MessageParcel &reply)
{
    int maxOsAccountNumber = 0;
    ErrCode result = QueryMaxOsAccountNumber(maxOsAccountNumber);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteInt32(maxOsAccountNumber)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcGetCreatedOsAccountsCount(MessageParcel &data, MessageParcel &reply)
{
    unsigned int osAccountsCount = 0;
    ErrCode result = GetCreatedOsAccountsCount(osAccountsCount);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteUint32(osAccountsCount)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcGetOsAccountAllConstraints(MessageParcel &data, MessageParcel &reply)
{
    int32_t localId;
    if (!data.ReadInt32(localId)) {
        ACCOUNT_LOGE("failed to read localId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    std::vector<std::string> constraints;
    ErrCode result = GetOsAccountAllConstraints(localId, constraints);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteStringVector(constraints)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcGetOsAccountLocalIdFromProcess(MessageParcel &data, MessageParcel &reply)
{
    int localId = -1;
    ErrCode result = GetOsAccountLocalIdFromProcess(localId);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteInt32(localId)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcIsMainOsAccount(MessageParcel &data, MessageParcel &reply)
{
    bool isMainOsAccount = false;
    ErrCode result = IsMainOsAccount(isMainOsAccount);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteBool(isMainOsAccount)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcGetOsAccountProfilePhoto(MessageParcel &data, MessageParcel &reply)
{
    int32_t localId;
    if (!data.ReadInt32(localId)) {
        ACCOUNT_LOGE("failed to read localId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    std::string photo;
    ErrCode result = GetOsAccountProfilePhoto(localId, photo);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteString(photo)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcGetOsAccountLocalIdFromDomain(MessageParcel &data, MessageParcel &reply)
{
    std::string domain = data.ReadString();
    std::string domainAccountName = data.ReadString();
    if (domain.empty() || domain.size() > Constants::DOMAIN_NAME_MAX_SIZE) {
        ACCOUNT_LOGE("failed to read string for domain name. length %{public}zu.", domain.size());
        reply.WriteInt32(ERR_OSACCOUNT_KIT_DOMAIN_NAME_LENGTH_INVALID_ERROR);
        return ERR_NONE;
    }

    if (domainAccountName.empty() || domainAccountName.size() > Constants::DOMAIN_ACCOUNT_NAME_MAX_SIZE) {
        ACCOUNT_LOGE("failed to read string for domainAccountName. length %{public}zu.", domainAccountName.size());
        reply.WriteInt32(ERR_OSACCOUNT_KIT_DOMAIN_ACCOUNT_NAME_LENGTH_INVALID_ERROR);
        return ERR_NONE;
    }

    int localId = -1;
    DomainAccountInfo domainInfo(domain, domainAccountName);
    ErrCode result = GetOsAccountLocalIdFromDomain(domainInfo, localId);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteInt32(localId)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcGetOsAccountTypeFromProcess(MessageParcel &data, MessageParcel &reply)
{
    OsAccountType type = OsAccountType::ADMIN;
    ErrCode result = GetOsAccountTypeFromProcess(type);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteInt32(type)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcGetApplicationConstraints(MessageParcel &data, MessageParcel &reply)
{
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcGetApplicationConstraintsByNumber(MessageParcel &data, MessageParcel &reply)
{
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcGetOsAccountLocalIdBySerialNumber(MessageParcel &data, MessageParcel &reply)
{
    int64_t serialNumber = data.ReadInt64();
    int id = 0;
    ErrCode result = GetOsAccountLocalIdBySerialNumber(serialNumber, id);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteInt32(id)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcGetSerialNumberByOsAccountLocalId(MessageParcel &data, MessageParcel &reply)
{
    int id = data.ReadInt32();
    int64_t serialNumber = 0;
    ErrCode result = GetSerialNumberByOsAccountLocalId(id, serialNumber);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteInt64(serialNumber)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcIsOsAccountActived(MessageParcel &data, MessageParcel &reply)
{
    int32_t localId;
    if (!data.ReadInt32(localId)) {
        ACCOUNT_LOGE("failed to read localId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    bool isOsAccountActived = false;
    ErrCode result = IsOsAccountActived(localId, isOsAccountActived);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteBool(isOsAccountActived)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcCheckOsAccountConstraintEnabled(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    int32_t localId;
    if (!data.ReadInt32(localId)) {
        ACCOUNT_LOGE("failed to read localId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    std::string constraint = data.ReadString();
    if (constraint.empty() || constraint.size() > Constants::CONSTRAINT_MAX_SIZE) {
        ACCOUNT_LOGE("failed to read string for constraint. length %{public}zu.", constraint.size());
        reply.WriteInt32(ERR_OSACCOUNT_KIT_READ_CONSTRAINTS_ERROR);
        return ERR_NONE;
    }

    bool isEnabled = false;
    ErrCode result = ERR_OK;
    if (code == static_cast<uint32_t>(IOsAccount::Message::IS_OS_ACCOUNT_CONSTRAINT_ENABLE)) {
        result = IsOsAccountConstraintEnable(localId, constraint, isEnabled);
    } else if (code == static_cast<uint32_t>(IOsAccount::Message::CHECK_OS_ACCOUNT_CONSTRAINT_ENABLED)) {
        result = CheckOsAccountConstraintEnabled(localId, constraint, isEnabled);
    } else {
        ACCOUNT_LOGE("stub code is invalid");
        return IPC_INVOKER_ERR;
    }
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteBool(isEnabled)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcIsOsAccountConstraintEnable(MessageParcel &data, MessageParcel &reply)
{
    return ProcCheckOsAccountConstraintEnabled(
        static_cast<uint32_t>(IOsAccount::Message::IS_OS_ACCOUNT_CONSTRAINT_ENABLE), data, reply);
}

ErrCode OsAccountStub::ProcCheckOsAccountConstraintEnabled(MessageParcel &data, MessageParcel &reply)
{
    return ProcCheckOsAccountConstraintEnabled(
        static_cast<uint32_t>(IOsAccount::Message::CHECK_OS_ACCOUNT_CONSTRAINT_ENABLED), data, reply);
}

ErrCode OsAccountStub::ProcIsMultiOsAccountEnable(MessageParcel &data, MessageParcel &reply)
{
    bool isMultiOsAccountEnable = false;
    ErrCode result = IsMultiOsAccountEnable(isMultiOsAccountEnable);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteBool(isMultiOsAccountEnable)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcIsOsAccountVerified(MessageParcel &data, MessageParcel &reply)
{
    int32_t localId;
    if (!data.ReadInt32(localId)) {
        ACCOUNT_LOGE("failed to read localId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    bool isVerified = false;
    ErrCode result = IsOsAccountVerified(localId, isVerified);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteBool(isVerified)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcIsOsAccountExists(MessageParcel &data, MessageParcel &reply)
{
    int32_t localId;
    if (!data.ReadInt32(localId)) {
        ACCOUNT_LOGE("failed to read localId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    bool isOsAccountExists = false;
    ErrCode result = IsOsAccountExists(localId, isOsAccountExists);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteBool(isOsAccountExists)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcSubscribeOsAccount(MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<OsAccountSubscribeInfo> subscribeInfo(data.ReadParcelable<OsAccountSubscribeInfo>());
    if (!subscribeInfo) {
        ACCOUNT_LOGE("failed to read parcelable for subscribeInfo");
        return IPC_STUB_INVALID_DATA_ERR;
    }

    sptr<IRemoteObject> eventListener = data.ReadRemoteObject();
    if (eventListener == nullptr) {
        ACCOUNT_LOGE("failed to read remote object for eventListener");
        return IPC_STUB_INVALID_DATA_ERR;
    }

    ErrCode result = SubscribeOsAccount(*subscribeInfo, eventListener);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }

    return ERR_NONE;
}

ErrCode OsAccountStub::ProcUnsubscribeOsAccount(MessageParcel &data, MessageParcel &reply)
{
    sptr<IRemoteObject> eventListener = data.ReadRemoteObject();
    if (eventListener == nullptr) {
        ACCOUNT_LOGE("failed to read remote object for eventListener");
        return IPC_STUB_INVALID_DATA_ERR;
    }

    ErrCode result = UnsubscribeOsAccount(eventListener);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcActivateOsAccount(MessageParcel &data, MessageParcel &reply)
{
    int32_t localId;
    if (!data.ReadInt32(localId)) {
        ACCOUNT_LOGE("failed to read localId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    ErrCode result = ActivateOsAccount(localId);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcStartOsAccount(MessageParcel &data, MessageParcel &reply)
{
    int32_t localId;
    if (!data.ReadInt32(localId)) {
        ACCOUNT_LOGE("failed to read localId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    ErrCode result = StartOsAccount(localId);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcStopOsAccount(MessageParcel &data, MessageParcel &reply)
{
    int32_t localId;
    if (!data.ReadInt32(localId)) {
        ACCOUNT_LOGE("failed to read localId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    ErrCode result = StopOsAccount(localId);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcGetOsAccountSwitchMod(MessageParcel &data, MessageParcel &reply)
{
    OS_ACCOUNT_SWITCH_MOD osAccountSwitchMod = GetOsAccountSwitchMod();
    if (!reply.WriteInt32(osAccountSwitchMod)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcIsCurrentOsAccountVerified(MessageParcel &data, MessageParcel &reply)
{
    bool isVerified = false;
    ErrCode result = IsCurrentOsAccountVerified(isVerified);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    reply.WriteBool(isVerified);
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcIsOsAccountCompleted(MessageParcel &data, MessageParcel &reply)
{
    int32_t localId;
    if (!data.ReadInt32(localId)) {
        ACCOUNT_LOGE("failed to read localId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    bool isOsAccountCompleted = false;
    ErrCode result = IsOsAccountCompleted(localId, isOsAccountCompleted);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    reply.WriteBool(isOsAccountCompleted);
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcSetCurrentOsAccountIsVerified(MessageParcel &data, MessageParcel &reply)
{
    bool isVerified = data.ReadBool();
    ErrCode result = SetCurrentOsAccountIsVerified(isVerified);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcSetOsAccountIsVerified(MessageParcel &data, MessageParcel &reply)
{
    int32_t localId;
    if (!data.ReadInt32(localId)) {
        ACCOUNT_LOGE("failed to read localId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    bool isVerified = data.ReadBool();
    ErrCode result = SetOsAccountIsVerified(localId, isVerified);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcDumpState(MessageParcel &data, MessageParcel &reply)
{
    int32_t id = data.ReadInt32();
    std::vector<std::string> state;

    ErrCode result = DumpState(id, state);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }

    if (!reply.WriteUint32(state.size())) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }

    for (auto info : state) {
        if (!reply.WriteString(info)) {
            ACCOUNT_LOGE("failed to write reply");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }
    }

    return ERR_NONE;
}

ErrCode OsAccountStub::ProcGetCreatedOsAccountNumFromDatabase(MessageParcel &data, MessageParcel &reply)
{
    std::string storeID = data.ReadString();
    int createdOsAccountNum = -1;
    ErrCode result = GetCreatedOsAccountNumFromDatabase(storeID, createdOsAccountNum);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteInt32(createdOsAccountNum)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcGetSerialNumberFromDatabase(MessageParcel &data, MessageParcel &reply)
{
    std::string storeID = data.ReadString();
    int64_t serialNumber = -1;
    ErrCode result = GetSerialNumberFromDatabase(storeID, serialNumber);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteInt64(serialNumber)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcGetMaxAllowCreateIdFromDatabase(MessageParcel &data, MessageParcel &reply)
{
    std::string storeID = data.ReadString();
    int id = -1;
    ErrCode result = GetMaxAllowCreateIdFromDatabase(storeID, id);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteInt32(id)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcGetOsAccountFromDatabase(MessageParcel &data, MessageParcel &reply)
{
    std::string storeID = data.ReadString();
    int id = data.ReadInt32();
    OsAccountInfo osAccountInfo;
    ErrCode result = GetOsAccountFromDatabase(storeID, id, osAccountInfo);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteParcelable(&osAccountInfo)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcGetOsAccountListFromDatabase(MessageParcel &data, MessageParcel &reply)
{
    std::string storeID = data.ReadString();
    std::vector<OsAccountInfo> osAccountList;
    ErrCode result = GetOsAccountListFromDatabase(storeID, osAccountList);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!WriteParcelableVector(osAccountList, reply)) {
        ACCOUNT_LOGE("ProcGetOsAccountListFromDatabase osAccountInfos failed stub");
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcQueryActiveOsAccountIds(MessageParcel &data, MessageParcel &reply)
{
    std::vector<int32_t> ids;
    ErrCode result = QueryActiveOsAccountIds(ids);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteInt32Vector(ids)) {
        ACCOUNT_LOGE("failed to write active list");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcQueryOsAccountConstraintSourceTypes(MessageParcel &data, MessageParcel &reply)
{
    int32_t localId;
    if (!data.ReadInt32(localId)) {
        ACCOUNT_LOGE("failed to read localId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    std::string constraint;
    if (!data.ReadString(constraint)) {
        ACCOUNT_LOGE("failed to read constraint");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }

    std::vector<ConstraintSourceTypeInfo> constraintSourceTypeInfos;
    ErrCode result = QueryOsAccountConstraintSourceTypes(localId, constraint, constraintSourceTypeInfos);
    if (!reply.WriteInt32(result)|| (!reply.WriteUint32(constraintSourceTypeInfos.size()))) {
        ACCOUNT_LOGE("QueryOsAccountConstraintSourceTypes failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    for (auto constraintInfo : constraintSourceTypeInfos) {
        if ((!reply.WriteInt32(constraintInfo.localId)) || (!reply.WriteInt32(constraintInfo.typeInfo))) {
            ACCOUNT_LOGE("failed to write reply");
            return IPC_STUB_WRITE_PARCEL_ERR;
        }
    }

    return ERR_NONE;
}

ErrCode OsAccountStub::ProcSetGlobalOsAccountConstraints(MessageParcel &data, MessageParcel &reply)
{
    std::vector<std::string> constraints;
    bool stringVectorReadSucess = data.ReadStringVector(&constraints);
    if (!stringVectorReadSucess) {
        ACCOUNT_LOGE("failed to read StringVector for constraints");
        return ERR_OSACCOUNT_KIT_READ_STRING_VECTOR_CONSTRAINTS_ERROR;
    }
    bool enable = data.ReadBool();
    int enforcerId = data.ReadInt32();
    if (enforcerId < 0) {
        ACCOUNT_LOGE("failed to read int for localId");
        reply.WriteInt32(ERR_OSACCOUNT_KIT_READ_IN_LOCAL_ID_ERROR);
        return ERR_NONE;
    }
    bool isDeviceOwner = data.ReadBool();
    ErrCode result = SetGlobalOsAccountConstraints(constraints, enable, enforcerId, isDeviceOwner);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcSetSpecificOsAccountConstraints(MessageParcel &data, MessageParcel &reply)
{
    std::vector<std::string> constraints;
    bool stringVectorReadSucess = data.ReadStringVector(&constraints);
    if (!stringVectorReadSucess) {
        ACCOUNT_LOGE("failed to read StringVector for constraints");
        return ERR_OSACCOUNT_KIT_READ_STRING_VECTOR_CONSTRAINTS_ERROR;
    }
    bool enable = data.ReadBool();
    int targetId = data.ReadInt32();
    if (targetId < 0) {
        ACCOUNT_LOGE("failed to read int for targetId");
        reply.WriteInt32(ERR_OSACCOUNT_KIT_READ_IN_LOCAL_ID_ERROR);
        return ERR_NONE;
    }
    int enforcerId = data.ReadInt32();
    if (enforcerId < 0) {
        ACCOUNT_LOGE("failed to read int for enforcerId");
        reply.WriteInt32(ERR_OSACCOUNT_KIT_READ_IN_LOCAL_ID_ERROR);
        return ERR_NONE;
    }
    bool isDeviceOwner = data.ReadBool();
    ErrCode result = SetSpecificOsAccountConstraints(constraints, enable, targetId, enforcerId, isDeviceOwner);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}
}  // namespace AccountSA
}  // namespace OHOS
