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
#include "os_account_stub.h"
#include "account_log_wrapper.h"
#include "account_permission_manager.h"
#include "account_constants.h"
#include "idomain_account_callback.h"
#include "ipc_skeleton.h"
#include "memory_guard.h"
#ifdef HICOLLIE_ENABLE
#include "xcollie/xcollie.h"
#endif // HICOLLIE_ENABLE
namespace OHOS {
namespace AccountSA {
const std::map<uint32_t, OsAccountStub::OsAccountMessageProc> messageProcMap = {
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::CREATE_OS_ACCOUNT),
        {
            .messageProcFunction = &OsAccountStub::ProcCreateOsAccount,
            .isSyetemApi = true,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::CREATE_OS_ACCOUNT_WITH_SHORT_NAME),
        {
            .messageProcFunction = &OsAccountStub::ProcCreateOsAccountWithShortName,
            .isSyetemApi = true,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::CREATE_OS_ACCOUNT_WITH_FULL_INFO),
        {
            .messageProcFunction = &OsAccountStub::ProcCreateOsAccountWithFullInfo,
            .isSyetemApi = true,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::UPDATE_OS_ACCOUNT_WITH_FULL_INFO),
        {
            .messageProcFunction = &OsAccountStub::ProcUpdateOsAccountWithFullInfo,
            .isSyetemApi = true,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::CREATE_OS_ACCOUNT_FOR_DOMAIN),
        {
            .messageProcFunction = &OsAccountStub::ProcCreateOsAccountForDomain,
            .isSyetemApi = true,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::REMOVE_OS_ACCOUNT),
        {
            .messageProcFunction = &OsAccountStub::ProcRemoveOsAccount,
            .isSyetemApi = true,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::IS_OS_ACCOUNT_EXISTS),
        {
            .messageProcFunction = &OsAccountStub::ProcIsOsAccountExists,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::IS_OS_ACCOUNT_ACTIVED),
        {
            .messageProcFunction = &OsAccountStub::ProcIsOsAccountActived,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::IS_OS_ACCOUNT_CONSTRAINT_ENABLE),
        {
            .messageProcFunction = &OsAccountStub::ProcIsOsAccountConstraintEnable,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::CHECK_OS_ACCOUNT_CONSTRAINT_ENABLED),
        {
            .messageProcFunction = &OsAccountStub::ProcCheckOsAccountConstraintEnabled,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::IS_OS_ACCOUNT_VERIFIED),
        {
            .messageProcFunction = &OsAccountStub::ProcIsOsAccountVerified,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::GET_CREATED_OS_ACCOUNT_COUNT),
        {
            .messageProcFunction = &OsAccountStub::ProcGetCreatedOsAccountsCount,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::GET_OS_ACCOUNT_LOCAL_ID_FROM_PROCESS),
        {
            .messageProcFunction = &OsAccountStub::ProcGetOsAccountLocalIdFromProcess,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::IS_MAIN_OS_ACCOUNT),
        {
            .messageProcFunction = &OsAccountStub::ProcIsMainOsAccount,
            .isSyetemApi = true,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::GET_OS_ACCOUNT_LOCAL_ID_FROM_DOMAIN),
        {
            .messageProcFunction = &OsAccountStub::ProcGetOsAccountLocalIdFromDomain,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::QUERY_MAX_OS_ACCOUNT_NUMBER),
        {
            .messageProcFunction = &OsAccountStub::ProcQueryMaxOsAccountNumber,
            .isSyetemApi = true,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::QUERY_MAX_LOGGED_IN_OS_ACCOUNT_NUMBER),
        {
            .messageProcFunction = &OsAccountStub::ProcQueryMaxLoggedInOsAccountNumber,
            .isSyetemApi = true,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::GET_OS_ACCOUNT_ALL_CONSTRAINTS),
        {
            .messageProcFunction = &OsAccountStub::ProcGetOsAccountAllConstraints,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::QUERY_ALL_CREATED_OS_ACCOUNTS),
        {
            .messageProcFunction = &OsAccountStub::ProcQueryAllCreatedOsAccounts,
            .isSyetemApi = true,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::QUERY_CURRENT_OS_ACCOUNT),
        {
            .messageProcFunction = &OsAccountStub::ProcQueryCurrentOsAccount,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::QUERY_OS_ACCOUNT_BY_ID),
        {
            .messageProcFunction = &OsAccountStub::ProcQueryOsAccountById,
            .isSyetemApi = true,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::GET_OS_ACCOUNT_TYPE_FROM_PROCESS),
        {
            .messageProcFunction = &OsAccountStub::ProcGetOsAccountTypeFromProcess,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::GET_OS_ACCOUNT_TYPE),
        {
            .messageProcFunction = &OsAccountStub::ProcGetOsAccountType,
            .isSyetemApi = true,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::GET_OS_ACCOUNT_PROFILE_PHOTO),
        {
            .messageProcFunction = &OsAccountStub::ProcGetOsAccountProfilePhoto,
            .isSyetemApi = true,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::IS_MULTI_OS_ACCOUNT_ENABLE),
        {
            .messageProcFunction = &OsAccountStub::ProcIsMultiOsAccountEnable,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::SET_OS_ACCOUNT_NAME),
        {
            .messageProcFunction = &OsAccountStub::ProcSetOsAccountName,
            .isSyetemApi = true,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::SET_OS_ACCOUNT_CONSTRAINTS),
        {
            .messageProcFunction = &OsAccountStub::ProcSetOsAccountConstraints,
            .isSyetemApi = true,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::SET_OS_ACCOUNT_PROFILE_PHOTO),
        {
            .messageProcFunction = &OsAccountStub::ProcSetOsAccountProfilePhoto,
            .isSyetemApi = true,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::ACTIVATE_OS_ACCOUNT),
        {
            .messageProcFunction = &OsAccountStub::ProcActivateOsAccount,
            .isSyetemApi = true,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::DEACTIVATE_OS_ACCOUNT),
        {
            .messageProcFunction = &OsAccountStub::ProcDeactivateOsAccount,
            .isSyetemApi = true,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::DEACTIVATE_ALL_OS_ACCOUNTS),
        {
            .messageProcFunction = &OsAccountStub::ProcDeactivateAllOsAccounts,
            .isSyetemApi = true,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::START_OS_ACCOUNT),
        {
            .messageProcFunction = &OsAccountStub::ProcStartOsAccount,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::SUBSCRIBE_OS_ACCOUNT),
        {
            .messageProcFunction = &OsAccountStub::ProcSubscribeOsAccount,
            .isSyetemApi = true,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::UNSUBSCRIBE_OS_ACCOUNT),
        {
            .messageProcFunction = &OsAccountStub::ProcUnsubscribeOsAccount,
            .isSyetemApi = true,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::GET_OS_ACCOUNT_LOCAL_ID_FOR_SERIAL_NUMBER),
        {
            .messageProcFunction = &OsAccountStub::ProcGetOsAccountLocalIdBySerialNumber,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::GET_SERIAL_NUMBER_FOR_OS_ACCOUNT),
        {
            .messageProcFunction = &OsAccountStub::ProcGetSerialNumberByOsAccountLocalId,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::GET_OS_ACCOUNT_SWITCH_MOD),
        {
            .messageProcFunction = &OsAccountStub::ProcGetOsAccountSwitchMod,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::IS_CURRENT_OS_ACCOUNT_VERIFIED),
        {
            .messageProcFunction = &OsAccountStub::ProcIsCurrentOsAccountVerified,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::IS_OS_ACCOUNT_COMPLETED),
        {
            .messageProcFunction = &OsAccountStub::ProcIsOsAccountCompleted,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::SET_CURRENT_OS_ACCOUNT_IS_VERIFIED),
        {
            .messageProcFunction = &OsAccountStub::ProcSetCurrentOsAccountIsVerified,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::SET_OS_ACCOUNT_IS_VERIFIED),
        {
            .messageProcFunction = &OsAccountStub::ProcSetOsAccountIsVerified,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::DUMP_STATE),
        {
            .messageProcFunction = &OsAccountStub::ProcDumpState,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::GET_CREATED_OS_ACCOUNT_NUM_FROM_DATABASE),
        {
            .messageProcFunction = &OsAccountStub::ProcGetCreatedOsAccountNumFromDatabase,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::GET_SERIAL_NUM_FROM_DATABASE),
        {
            .messageProcFunction = &OsAccountStub::ProcGetSerialNumberFromDatabase,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::GET_MAX_ALLOW_CREATE_ID_FROM_DATABASE),
        {
            .messageProcFunction = &OsAccountStub::ProcGetMaxAllowCreateIdFromDatabase,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::GET_OS_ACCOUNT_FROM_DATABASE),
        {
            .messageProcFunction = &OsAccountStub::ProcGetOsAccountFromDatabase,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::GET_OS_ACCOUNT_LIST_FROM_DATABASE),
        {
            .messageProcFunction = &OsAccountStub::ProcGetOsAccountListFromDatabase,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::QUERY_ACTIVE_OS_ACCOUNT_IDS),
        {
            .messageProcFunction = &OsAccountStub::ProcQueryActiveOsAccountIds,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::QUERY_OS_ACCOUNT_CONSTRAINT_SOURCE_TYPES),
        {
            .messageProcFunction = &OsAccountStub::ProcQueryOsAccountConstraintSourceTypes,
            .isSyetemApi = true,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::SET_GLOBAL_OS_ACCOUNT_CONSTRAINTS),
        {
            .messageProcFunction = &OsAccountStub::ProcSetGlobalOsAccountConstraints,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::SET_SPECIFIC_OS_ACCOUNT_CONSTRAINTS),
        {
            .messageProcFunction = &OsAccountStub::ProcSetSpecificOsAccountConstraints,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::SET_DEFAULT_ACTIVATED_OS_ACCOUNT),
        {
            .messageProcFunction = &OsAccountStub::ProcSetDefaultActivatedOsAccount,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::GET_DEFAULT_ACTIVATED_OS_ACCOUNT),
        {
            .messageProcFunction = &OsAccountStub::ProcGetDefaultActivatedOsAccount,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::GET_OS_ACCOUNT_SHORT_NAME),
        {
            .messageProcFunction = &OsAccountStub::ProcGetOsAccountShortName,
            .isSyetemApi = true,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::GET_OS_ACCOUNT_NAME),
        {
            .messageProcFunction = &OsAccountStub::ProcGetOsAccountName,
            .isSyetemApi = false,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::IS_OS_ACCOUNT_FOREGROUND),
        {
            .messageProcFunction = &OsAccountStub::ProcIsOsAccountForeground,
            .isSyetemApi = true,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::GET_FOREGROUND_OS_ACCOUNT_LOCAL_ID),
        {
            .messageProcFunction = &OsAccountStub::ProcGetForegroundOsAccountLocalId,
            .isSyetemApi = true,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::GET_FOREGROUND_OS_ACCOUNTS),
        {
            .messageProcFunction = &OsAccountStub::ProcGetForegroundOsAccounts,
            .isSyetemApi = true,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::GET_BACKGROUND_OS_ACCOUNT_LOCAL_IDS),
        {
            .messageProcFunction = &OsAccountStub::ProcGetBackgroundOsAccountLocalIds,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::GET_OS_ACCOUNT_SHORT_NAME_BY_ID),
        {
            .messageProcFunction = &OsAccountStub::ProcGetOsAccountShortNameById,
            .isSyetemApi = true,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::SET_OS_ACCOUNT_TO_BE_REMOVED),
        {
            .messageProcFunction = &OsAccountStub::ProcSetOsAccountToBeRemoved,
            .isSyetemApi = true,
        }
    },
};

OsAccountStub::OsAccountStub()
{
    messageProcMap_ = messageProcMap;
}

OsAccountStub::~OsAccountStub()
{}

int OsAccountStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    ACCOUNT_LOGD("Received stub message: %{public}d, callingUid: %{public}d", code, IPCSkeleton::GetCallingUid());
    MemoryGuard cacheGuard;
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        ACCOUNT_LOGE("check descriptor failed! code %{public}u.", code);
        return ERR_ACCOUNT_COMMON_CHECK_DESCRIPTOR_ERROR;
    }

#ifdef HICOLLIE_ENABLE
    int timerId =
        HiviewDFX::XCollie::GetInstance().SetTimer(TIMER_NAME, TIMEOUT, nullptr, nullptr, HiviewDFX::XCOLLIE_FLAG_LOG);
#endif // HICOLLIE_ENABLE

    auto messageProc = messageProcMap_.find(code);
    if (messageProc != messageProcMap_.end()) {
        auto messageProcFunction = messageProc->second;
        if (messageProcFunction.isSyetemApi) {
            ErrCode result = AccountPermissionManager::CheckSystemApp();
            if (result != ERR_OK) {
                ACCOUNT_LOGE("is not system application, result = %{public}u.", result);
#ifdef HICOLLIE_ENABLE
                HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
#endif // HICOLLIE_ENABLE
                return result;
            }
        }
        int ret = (this->*messageProcFunction.messageProcFunction)(data, reply);
#ifdef HICOLLIE_ENABLE
        HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
#endif // HICOLLIE_ENABLE
        return ret;
    }
#ifdef HICOLLIE_ENABLE
    HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
#endif // HICOLLIE_ENABLE
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

static ErrCode WriteResultWithOsAccountInfo(MessageParcel &reply, int32_t result, const OsAccountInfo &info)
{
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write result");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteParcelable(&info)) {
        ACCOUNT_LOGE("failed to write os account info");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcCreateOsAccount(MessageParcel &data, MessageParcel &reply)
{
    std::string name;
    if (!data.ReadString(name)) {
        ACCOUNT_LOGE("failed to read string for name");
        reply.WriteInt32(ERR_OSACCOUNT_KIT_READ_LOCALNAME_ERROR);
        return ERR_NONE;
    }
    OsAccountType type = static_cast<OsAccountType>(data.ReadInt32());
    OsAccountInfo osAccountInfo;
    ErrCode result = CreateOsAccount(name, type, osAccountInfo);
    return WriteResultWithOsAccountInfo(reply, result, osAccountInfo);
}

ErrCode OsAccountStub::ProcCreateOsAccountWithShortName(MessageParcel &data, MessageParcel &reply)
{
    std::string localName;
    if (!data.ReadString(localName)) {
        ACCOUNT_LOGE("failed to read string for local name");
        reply.WriteInt32(ERR_OSACCOUNT_KIT_READ_LOCALNAME_ERROR);
        return ERR_NONE;
    }
    std::string shortName;
    if (!data.ReadString(shortName)) {
        ACCOUNT_LOGE("failed to read string for short name");
        reply.WriteInt32(ERR_OSACCOUNT_KIT_READ_LOCALNAME_ERROR);
        return ERR_NONE;
    }
    int32_t type = 0;
    if (!data.ReadInt32(type)) {
        ACCOUNT_LOGE("failed to read int for account type");
        reply.WriteInt32(ERR_OSACCOUNT_KIT_READ_LOCALNAME_ERROR);
        return ERR_NONE;
    }
    OsAccountType osAccountType = static_cast<OsAccountType>(type);
    sptr<CreateOsAccountOptions> options = data.ReadParcelable<CreateOsAccountOptions>();
    if (options == nullptr) {
        ACCOUNT_LOGE("read options failed");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    OsAccountInfo osAccountInfo;
    ErrCode result = CreateOsAccount(localName, shortName, osAccountType, osAccountInfo, *options);
    return WriteResultWithOsAccountInfo(reply, result, osAccountInfo);
}


ErrCode OsAccountStub::ProcCreateOsAccountWithFullInfo(MessageParcel &data, MessageParcel &reply)
{
    std::shared_ptr<OsAccountInfo> info(data.ReadParcelable<OsAccountInfo>());
    if (info == nullptr) {
        ACCOUNT_LOGE("failed to read OsAccountInfo");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }

    ErrCode code = info->ParamCheck();
    if (code != ERR_OK) {
        ACCOUNT_LOGE("OsAccountInfo required field is invalidate");
        return code;
    }

    ErrCode result = CreateOsAccountWithFullInfo(*info);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write result");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcUpdateOsAccountWithFullInfo(MessageParcel &data, MessageParcel &reply)
{
    std::shared_ptr<OsAccountInfo> info(data.ReadParcelable<OsAccountInfo>());
    if (info == nullptr) {
        ACCOUNT_LOGE("failed to read OsAccountInfo");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }

    ErrCode code = info->ParamCheck();
    if (code != ERR_OK) {
        ACCOUNT_LOGE("OsAccountInfo required field is invalidate");
        return code;
    }

    ErrCode result = UpdateOsAccountWithFullInfo(*info);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write result");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcCreateOsAccountForDomain(MessageParcel &data, MessageParcel &reply)
{
    OsAccountType type = static_cast<OsAccountType>(data.ReadInt32());
    std::shared_ptr<DomainAccountInfo> info(data.ReadParcelable<DomainAccountInfo>());
    if (info == nullptr) {
        ACCOUNT_LOGE("failed to read domain account info");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }

    if (info->domain_.empty() || info->domain_.size() > Constants::DOMAIN_NAME_MAX_SIZE) {
        ACCOUNT_LOGE("read invalid domain length %{public}zu.", info->domain_.size());
        reply.WriteInt32(ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
        return ERR_NONE;
    }

    if (info->accountName_.empty() || info->accountName_.size() > Constants::LOCAL_NAME_MAX_SIZE) {
        ACCOUNT_LOGE("read invalid domain account name length %{public}zu.", info->accountName_.size());
        reply.WriteInt32(ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
        return ERR_NONE;
    }

    OsAccountInfo osAccountInfo;
    auto callback = iface_cast<IDomainAccountCallback>(data.ReadRemoteObject());
    if (callback == nullptr) {
        ACCOUNT_LOGE("failed to read parcel");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }

    sptr<CreateOsAccountForDomainOptions> options = data.ReadParcelable<CreateOsAccountForDomainOptions>();
    if (options == nullptr) {
        ACCOUNT_LOGE("Read options failed");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    ErrCode result = CreateOsAccountForDomain(type, *info, callback, *options);
    return WriteResultWithOsAccountInfo(reply, result, osAccountInfo);
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
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
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
    return WriteResultWithOsAccountInfo(reply, result, osAccountInfo);
}

ErrCode OsAccountStub::ProcQueryCurrentOsAccount(MessageParcel &data, MessageParcel &reply)
{
    OsAccountInfo osAccountInfo = OsAccountInfo();
    ErrCode result = QueryCurrentOsAccount(osAccountInfo);
    return WriteResultWithOsAccountInfo(reply, result, osAccountInfo);
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
    uint32_t maxOsAccountNumber = 0;
    ErrCode result = QueryMaxOsAccountNumber(maxOsAccountNumber);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteUint32(maxOsAccountNumber)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcQueryMaxLoggedInOsAccountNumber(MessageParcel &data, MessageParcel &reply)
{
    uint32_t maxNum = 0;
    ErrCode result = QueryMaxLoggedInOsAccountNumber(maxNum);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteUint32(maxNum)) {
        ACCOUNT_LOGE("Failed to write reply");
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
        reply.WriteInt32(ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
        return ERR_NONE;
    }

    if (domainAccountName.empty() || domainAccountName.size() > Constants::LOCAL_NAME_MAX_SIZE) {
        ACCOUNT_LOGE("failed to read string for domainAccountName. length %{public}zu.", domainAccountName.size());
        reply.WriteInt32(ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
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
    if (!reply.WriteInt32(static_cast<int32_t>(type))) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcGetOsAccountType(MessageParcel &data, MessageParcel &reply)
{
    OsAccountType type = OsAccountType::ADMIN;
    int32_t localId;
    if (!data.ReadInt32(localId)) {
        ACCOUNT_LOGE("Read localId failed.");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    ErrCode result = GetOsAccountType(localId, type);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Write reply failed.");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (result != ERR_OK) {
        return ERR_NONE;
    }
    if (!reply.WriteInt32(static_cast<int32_t>(type))) {
        ACCOUNT_LOGE("Write reply failed.");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
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
    if (code == static_cast<uint32_t>(OsAccountInterfaceCode::IS_OS_ACCOUNT_CONSTRAINT_ENABLE)) {
        result = IsOsAccountConstraintEnable(localId, constraint, isEnabled);
    } else if (code == static_cast<uint32_t>(OsAccountInterfaceCode::CHECK_OS_ACCOUNT_CONSTRAINT_ENABLED)) {
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
        static_cast<uint32_t>(OsAccountInterfaceCode::IS_OS_ACCOUNT_CONSTRAINT_ENABLE), data, reply);
}

ErrCode OsAccountStub::ProcCheckOsAccountConstraintEnabled(MessageParcel &data, MessageParcel &reply)
{
    return ProcCheckOsAccountConstraintEnabled(
        static_cast<uint32_t>(OsAccountInterfaceCode::CHECK_OS_ACCOUNT_CONSTRAINT_ENABLED), data, reply);
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

ErrCode OsAccountStub::ProcDeactivateOsAccount(MessageParcel &data, MessageParcel &reply)
{
    int32_t localId;
    if (!data.ReadInt32(localId)) {
        ACCOUNT_LOGE("failed to read localId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    ErrCode result = DeactivateOsAccount(localId);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcDeactivateAllOsAccounts(MessageParcel &data, MessageParcel &reply)
{
    ErrCode result = DeactivateAllOsAccounts();
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Write reply failed, result=%{public}d.", result);
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
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
    return WriteResultWithOsAccountInfo(reply, result, osAccountInfo);
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
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
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

ErrCode OsAccountStub::ProcSetDefaultActivatedOsAccount(MessageParcel &data, MessageParcel &reply)
{
    int32_t localId;
    if (!data.ReadInt32(localId)) {
        ACCOUNT_LOGE("failed to read localId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    ErrCode result = SetDefaultActivatedOsAccount(localId);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcGetDefaultActivatedOsAccount(MessageParcel &data, MessageParcel &reply)
{
    int32_t localId = 0;
    ErrCode result = GetDefaultActivatedOsAccount(localId);
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

ErrCode OsAccountStub::ProcGetOsAccountShortName(MessageParcel &data, MessageParcel &reply)
{
    std::string shortName;
    ErrCode result = GetOsAccountShortName(shortName);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteString(shortName)) {
        ACCOUNT_LOGE("failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcGetOsAccountName(MessageParcel &data, MessageParcel &reply)
{
    std::string name;
    ErrCode result = GetOsAccountName(name);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Failed to write result, result=%{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteString(name)) {
        ACCOUNT_LOGE("Failed to write name");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcGetOsAccountShortNameById(MessageParcel &data, MessageParcel &reply)
{
    int32_t id;
    if (!data.ReadInt32(id)) {
        ACCOUNT_LOGE("Read id failed.");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    std::string shortName;
    ErrCode result = GetOsAccountShortNameById(id, shortName);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Write result failed.");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (result != ERR_OK) {
        return ERR_NONE;
    }
    if (!reply.WriteString(shortName)) {
        ACCOUNT_LOGE("Write short name failed.");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcSetSpecificOsAccountConstraints(MessageParcel &data, MessageParcel &reply)
{
    std::vector<std::string> constraints;
    bool stringVectorReadSucess = data.ReadStringVector(&constraints);
    if (!stringVectorReadSucess) {
        ACCOUNT_LOGE("failed to read StringVector for constraints");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
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

ErrCode OsAccountStub::ProcIsOsAccountForeground(MessageParcel &data, MessageParcel &reply)
{
    int32_t localId;
    if (!data.ReadInt32(localId)) {
        ACCOUNT_LOGE("Read localId failed.");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    uint64_t displayId;
    if (!data.ReadUint64(displayId)) {
        ACCOUNT_LOGE("Read displayId failed.");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    bool isForeground = false;
    ErrCode result = IsOsAccountForeground(localId, displayId, isForeground);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Write result failed.");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (result != ERR_OK) {
        return result;
    }
    if (!reply.WriteBool(isForeground)) {
        ACCOUNT_LOGE("Write isForeground failed.");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcGetForegroundOsAccountLocalId(MessageParcel &data, MessageParcel &reply)
{
    uint64_t displayId;
    if (!data.ReadUint64(displayId)) {
        ACCOUNT_LOGE("Read displayId failed.");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    int32_t localId;
    ErrCode result = GetForegroundOsAccountLocalId(displayId, localId);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Write result failed.");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (result != ERR_OK) {
        return result;
    }
    if (!reply.WriteInt32(localId)) {
        ACCOUNT_LOGE("Write localId failed.");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcGetForegroundOsAccounts(MessageParcel &data, MessageParcel &reply)
{
    std::vector<ForegroundOsAccount> foregroundAccounts;
    ErrCode result = GetForegroundOsAccounts(foregroundAccounts);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Write result failed.");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (result != ERR_OK) {
        return result;
    }
    if (!reply.WriteUint32(foregroundAccounts.size())) {
        ACCOUNT_LOGE("Write foregroundAccounts size failed.");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    for (const auto &iter : foregroundAccounts) {
        if ((!reply.WriteInt32(iter.localId)) || (!reply.WriteUint64(iter.displayId))) {
            ACCOUNT_LOGE("Write ForegroundOsAccount failed.");
            return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
        }
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcGetBackgroundOsAccountLocalIds(MessageParcel &data, MessageParcel &reply)
{
    std::vector<int32_t> localIds;
    ErrCode result = GetBackgroundOsAccountLocalIds(localIds);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Write result failed.");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (result != ERR_OK) {
        return result;
    }
    if (!reply.WriteInt32Vector(localIds)) {
        ACCOUNT_LOGE("Write localIds failed.");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcSetOsAccountToBeRemoved(MessageParcel &data, MessageParcel &reply)
{
    int32_t localId;
    if (!data.ReadInt32(localId)) {
        ACCOUNT_LOGE("Read localId failed.");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    bool toBeRemoved = false;
    if (!data.ReadBool(toBeRemoved)) {
        ACCOUNT_LOGE("Read toBeRemoved failed.");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    ErrCode result = SetOsAccountToBeRemoved(localId, toBeRemoved);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Write result failed.");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    return ERR_NONE;
}
}  // namespace AccountSA
}  // namespace OHOS
