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
#include "account_info.h"
#include "account_hisysevent_adapter.h"
#include "hitrace_adapter.h"
#include "idomain_account_callback.h"
#include "ipc_skeleton.h"
#include "memory_guard.h"
#include "os_account_constants.h"
#ifdef HICOLLIE_ENABLE
#include "account_timer.h"
#include "xcollie/xcollie.h"
#endif // HICOLLIE_ENABLE
namespace OHOS {
namespace AccountSA {
#ifdef HICOLLIE_ENABLE
constexpr std::int32_t RECOVERY_TIMEOUT = 6; // timeout 6s
const std::set<uint32_t> WATCH_DOG_WHITE_LIST = {
    static_cast<uint32_t>(OsAccountInterfaceCode::CREATE_OS_ACCOUNT),
    static_cast<uint32_t>(OsAccountInterfaceCode::CREATE_OS_ACCOUNT_WITH_SHORT_NAME),
    static_cast<uint32_t>(OsAccountInterfaceCode::CREATE_OS_ACCOUNT_WITH_FULL_INFO),
    static_cast<uint32_t>(OsAccountInterfaceCode::CREATE_OS_ACCOUNT_FOR_DOMAIN),
};
#endif // HICOLLIE_ENABLE
static const std::map<uint32_t, OsAccountStub::OsAccountMessageProc> messageProcMap = {
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::CREATE_OS_ACCOUNT),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcCreateOsAccount(data, reply); },
            .isSystemApi = true,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::CREATE_OS_ACCOUNT_WITH_SHORT_NAME),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcCreateOsAccountWithShortName(data, reply); },
            .isSystemApi = true,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::CREATE_OS_ACCOUNT_WITH_FULL_INFO),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcCreateOsAccountWithFullInfo(data, reply); },
            .isSystemApi = true,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::UPDATE_OS_ACCOUNT_WITH_FULL_INFO),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcUpdateOsAccountWithFullInfo(data, reply); },
            .isSystemApi = true,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::CREATE_OS_ACCOUNT_FOR_DOMAIN),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcCreateOsAccountForDomain(data, reply); },
            .isSystemApi = true,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::REMOVE_OS_ACCOUNT),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcRemoveOsAccount(data, reply); },
            .isSystemApi = true,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::IS_OS_ACCOUNT_EXISTS),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcIsOsAccountExists(data, reply); },
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::IS_OS_ACCOUNT_ACTIVED),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcIsOsAccountActived(data, reply); },
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::IS_OS_ACCOUNT_CONSTRAINT_ENABLE),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcIsOsAccountConstraintEnable(data, reply); },
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::CHECK_OS_ACCOUNT_CONSTRAINT_ENABLED),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcCheckOsAccountConstraintEnabled(data, reply); },
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::IS_OS_ACCOUNT_VERIFIED),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcIsOsAccountVerified(data, reply); },
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::IS_OS_ACCOUNT_DEACTIVATING),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcIsOsAccountDeactivating(data, reply); },
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::GET_CREATED_OS_ACCOUNT_COUNT),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcGetCreatedOsAccountsCount(data, reply); },
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::GET_OS_ACCOUNT_LOCAL_ID_FROM_PROCESS),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcGetOsAccountLocalIdFromProcess(data, reply); },
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::IS_MAIN_OS_ACCOUNT),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcIsMainOsAccount(data, reply); },
            .isSystemApi = true,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::GET_OS_ACCOUNT_LOCAL_ID_FROM_DOMAIN),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcGetOsAccountLocalIdFromDomain(data, reply); },
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::QUERY_MAX_OS_ACCOUNT_NUMBER),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcQueryMaxOsAccountNumber(data, reply); },
            .isSystemApi = true,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::QUERY_MAX_LOGGED_IN_OS_ACCOUNT_NUMBER),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcQueryMaxLoggedInOsAccountNumber(data, reply); },
            .isSystemApi = true,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::GET_OS_ACCOUNT_ALL_CONSTRAINTS),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcGetOsAccountAllConstraints(data, reply); },
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::QUERY_ALL_CREATED_OS_ACCOUNTS),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcQueryAllCreatedOsAccounts(data, reply); },
            .isSystemApi = true,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::QUERY_CURRENT_OS_ACCOUNT),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcQueryCurrentOsAccount(data, reply); },
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::QUERY_OS_ACCOUNT_BY_ID),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcQueryOsAccountById(data, reply); },
            .isSystemApi = true,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::GET_OS_ACCOUNT_TYPE_FROM_PROCESS),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcGetOsAccountTypeFromProcess(data, reply); },
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::GET_OS_ACCOUNT_TYPE),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcGetOsAccountType(data, reply); },
            .isSystemApi = true,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::GET_OS_ACCOUNT_PROFILE_PHOTO),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcGetOsAccountProfilePhoto(data, reply); },
            .isSystemApi = true,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::IS_MULTI_OS_ACCOUNT_ENABLE),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcIsMultiOsAccountEnable(data, reply); },
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::SET_OS_ACCOUNT_NAME),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcSetOsAccountName(data, reply); },
            .isSystemApi = true,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::SET_OS_ACCOUNT_CONSTRAINTS),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcSetOsAccountConstraints(data, reply); },
            .isSystemApi = true,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::SET_OS_ACCOUNT_PROFILE_PHOTO),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcSetOsAccountProfilePhoto(data, reply); },
            .isSystemApi = true,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::ACTIVATE_OS_ACCOUNT),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcActivateOsAccount(data, reply); },
            .isSystemApi = true,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::DEACTIVATE_OS_ACCOUNT),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcDeactivateOsAccount(data, reply); },
            .isSystemApi = true,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::DEACTIVATE_ALL_OS_ACCOUNTS),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcDeactivateAllOsAccounts(data, reply); },
            .isSystemApi = true,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::START_OS_ACCOUNT),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcStartOsAccount(data, reply); },
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::SUBSCRIBE_OS_ACCOUNT),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcSubscribeOsAccount(data, reply); },
            .isSystemApi = true,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::UNSUBSCRIBE_OS_ACCOUNT),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcUnsubscribeOsAccount(data, reply); },
            .isSystemApi = true,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::GET_OS_ACCOUNT_LOCAL_ID_FOR_SERIAL_NUMBER),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcGetOsAccountLocalIdBySerialNumber(data, reply); },
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::GET_SERIAL_NUMBER_FOR_OS_ACCOUNT),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcGetSerialNumberByOsAccountLocalId(data, reply); },
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::GET_OS_ACCOUNT_SWITCH_MOD),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcGetOsAccountSwitchMod(data, reply); },
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::IS_CURRENT_OS_ACCOUNT_VERIFIED),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcIsCurrentOsAccountVerified(data, reply); },
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::IS_OS_ACCOUNT_COMPLETED),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcIsOsAccountCompleted(data, reply); },
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::SET_CURRENT_OS_ACCOUNT_IS_VERIFIED),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcSetCurrentOsAccountIsVerified(data, reply); },
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::SET_OS_ACCOUNT_IS_VERIFIED),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcSetOsAccountIsVerified(data, reply); },
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::DUMP_STATE),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcDumpState(data, reply); },
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::GET_CREATED_OS_ACCOUNT_NUM_FROM_DATABASE),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcGetCreatedOsAccountNumFromDatabase(data, reply); },
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::GET_SERIAL_NUM_FROM_DATABASE),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcGetSerialNumberFromDatabase(data, reply); },
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::GET_MAX_ALLOW_CREATE_ID_FROM_DATABASE),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcGetMaxAllowCreateIdFromDatabase(data, reply); },
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::GET_OS_ACCOUNT_FROM_DATABASE),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcGetOsAccountFromDatabase(data, reply); },
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::GET_OS_ACCOUNT_LIST_FROM_DATABASE),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcGetOsAccountListFromDatabase(data, reply); },
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::QUERY_ACTIVE_OS_ACCOUNT_IDS),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcQueryActiveOsAccountIds(data, reply); },
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::QUERY_OS_ACCOUNT_CONSTRAINT_SOURCE_TYPES),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcQueryOsAccountConstraintSourceTypes(data, reply); },
            .isSystemApi = true,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::SET_GLOBAL_OS_ACCOUNT_CONSTRAINTS),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcSetGlobalOsAccountConstraints(data, reply); },
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::SET_SPECIFIC_OS_ACCOUNT_CONSTRAINTS),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcSetSpecificOsAccountConstraints(data, reply); },
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::SET_DEFAULT_ACTIVATED_OS_ACCOUNT),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcSetDefaultActivatedOsAccount(data, reply); },
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::GET_DEFAULT_ACTIVATED_OS_ACCOUNT),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcGetDefaultActivatedOsAccount(data, reply); },
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::GET_OS_ACCOUNT_SHORT_NAME),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcGetOsAccountShortName(data, reply); },
            .isSystemApi = true,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::GET_OS_ACCOUNT_NAME),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcGetOsAccountName(data, reply); },
            .isSystemApi = false,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::GET_OS_ACCOUNT_NAME_BY_ID),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcGetOsAccountNameById(data, reply); },
            .isSystemApi = true,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::IS_OS_ACCOUNT_FOREGROUND),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcIsOsAccountForeground(data, reply); },
            .isSystemApi = true,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::GET_FOREGROUND_OS_ACCOUNT_LOCAL_ID),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcGetForegroundOsAccountLocalId(data, reply); },
            .isSystemApi = false,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::GET_FOREGROUND_OS_ACCOUNTS),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcGetForegroundOsAccounts(data, reply); },
            .isSystemApi = true,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::GET_BACKGROUND_OS_ACCOUNT_LOCAL_IDS),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcGetBackgroundOsAccountLocalIds(data, reply); },
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::GET_OS_ACCOUNT_SHORT_NAME_BY_ID),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcGetOsAccountShortNameById(data, reply); },
            .isSystemApi = true,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::SET_OS_ACCOUNT_TO_BE_REMOVED),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcSetOsAccountToBeRemoved(data, reply); },
            .isSystemApi = true,
        }
    },
    {
        static_cast<uint32_t>(OsAccountInterfaceCode::GET_OS_ACCOUNT_DOMAIN_INFO),
        {
            .messageProcFunction = [] (OsAccountStub *ptr, MessageParcel &data, MessageParcel &reply) {
                return ptr->ProcGetOsAccountDomainInfo(data, reply); },
            .isSystemApi = false,
        }
    },
};

OsAccountStub::OsAccountStub()
{}

OsAccountStub::~OsAccountStub()
{}

int OsAccountStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    ACCOUNT_LOGD("Received stub message: %{public}d, callingUid: %{public}d", code, IPCSkeleton::GetCallingUid());
    MemoryGuard cacheGuard;
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        ACCOUNT_LOGE("Check descriptor failed! code %{public}u.", code);
        return ERR_ACCOUNT_COMMON_CHECK_DESCRIPTOR_ERROR;
    }

#ifdef HICOLLIE_ENABLE
    AccountTimer timer(false);
    if (WATCH_DOG_WHITE_LIST.find(code) == WATCH_DOG_WHITE_LIST.end()) {
        timer.Init();
    }
#endif // HICOLLIE_ENABLE

    auto messageProc = messageProcMap.find(code);
    if (messageProc != messageProcMap.end()) {
        auto messageProcFunction = messageProc->second;
        if (messageProcFunction.isSystemApi) {
            ErrCode result = AccountPermissionManager::CheckSystemApp();
            if (result != ERR_OK) {
                ACCOUNT_LOGE("Is not system application, result = %{public}u.", result);
                return result;
            }
        }
        int ret = (messageProcFunction.messageProcFunction)(this, data, reply);
        return ret;
    }
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

bool OsAccountStub::WriteOsAccountInfoList(const std::vector<OsAccountInfo> &accounts, MessageParcel &data)
{
    nlohmann::json accountJsonArray;
    for (const auto &accountItem : accounts) {
        accountJsonArray.emplace_back(accountItem.ToJson());
    }
    std::string accountJsonArrayStr = accountJsonArray.dump();
    if (accountJsonArrayStr.size() >= Constants::IPC_WRITE_RAW_DATA_MAX_SIZE) {
        ACCOUNT_LOGE("AccountJsonArrayStr is too long");
        return false;
    }
    if (!data.WriteUint32(accountJsonArrayStr.size() + 1)) {
        ACCOUNT_LOGE("Failed to write accountJsonArrayStr size");
        return false;
    }
    if (!data.WriteRawData(accountJsonArrayStr.c_str(), accountJsonArrayStr.size() + 1)) {
        ACCOUNT_LOGE("Failed to write string for accountJsonArrayStr");
        return false;
    }
    return true;
}

static ErrCode WriteResultWithOsAccountInfo(MessageParcel &reply, int32_t result, const OsAccountInfo &info)
{
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Failed to write result");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    std::string accountStr = info.ToString();
    if (!reply.WriteInt32(accountStr.size() + 1)) {
        ACCOUNT_LOGE("Failed to write accountStr size");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (!reply.WriteRawData(accountStr.c_str(), accountStr.size() + 1)) {
        ACCOUNT_LOGE("Failed to write string for account");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcCreateOsAccount(MessageParcel &data, MessageParcel &reply)
{
    ACCOUNT_LOGI("Calling uid: %{public}d, pid: %{public}d",
        IPCSkeleton::GetCallingUid(), IPCSkeleton::GetCallingRealPid());
    std::string name;
    if (!data.ReadString(name)) {
        ACCOUNT_LOGE("Failed to read string for name");
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
    ACCOUNT_LOGI("Calling uid: %{public}d, pid: %{public}d",
        IPCSkeleton::GetCallingUid(), IPCSkeleton::GetCallingRealPid());
    std::string localName;
    if (!data.ReadString(localName)) {
        ACCOUNT_LOGE("Failed to read string for local name");
        reply.WriteInt32(ERR_OSACCOUNT_KIT_READ_LOCALNAME_ERROR);
        return ERR_NONE;
    }
    bool hasShortName;
    if (!data.ReadBool(hasShortName)) {
        ACCOUNT_LOGE("Failed to read bool for hasShortName");
        reply.WriteInt32(ERR_OSACCOUNT_KIT_READ_LOCALNAME_ERROR);
        return ERR_NONE;
    }
    std::string shortName;
    if (hasShortName && !data.ReadString(shortName)) {
        ACCOUNT_LOGE("Failed to read string for short name");
        reply.WriteInt32(ERR_OSACCOUNT_KIT_READ_LOCALNAME_ERROR);
        return ERR_NONE;
    }
    int32_t type = 0;
    if (!data.ReadInt32(type)) {
        ACCOUNT_LOGE("Failed to read int for account type");
        reply.WriteInt32(ERR_OSACCOUNT_KIT_READ_LOCALNAME_ERROR);
        return ERR_NONE;
    }
    OsAccountType osAccountType = static_cast<OsAccountType>(type);
    sptr<CreateOsAccountOptions> options = data.ReadParcelable<CreateOsAccountOptions>();
    if (options == nullptr) {
        ACCOUNT_LOGE("Read options failed");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    OsAccountInfo osAccountInfo;
    ErrCode result = CreateOsAccount(localName, shortName, osAccountType, osAccountInfo, *options);
    return WriteResultWithOsAccountInfo(reply, result, osAccountInfo);
}


ErrCode OsAccountStub::ProcCreateOsAccountWithFullInfo(MessageParcel &data, MessageParcel &reply)
{
    ACCOUNT_LOGI("Calling uid: %{public}d, pid: %{public}d",
        IPCSkeleton::GetCallingUid(), IPCSkeleton::GetCallingRealPid());
    std::shared_ptr<OsAccountInfo> info(data.ReadParcelable<OsAccountInfo>());
    if (info == nullptr) {
        ACCOUNT_LOGE("Failed to read OsAccountInfo");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }

    ErrCode code = info->ParamCheck();
    if (code != ERR_OK) {
        ACCOUNT_LOGE("OsAccountInfo required field is invalidate");
        return code;
    }

    sptr<CreateOsAccountOptions> options = data.ReadParcelable<CreateOsAccountOptions>();
    if (options == nullptr) {
        ACCOUNT_LOGE("Read options failed");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }

    ErrCode result = CreateOsAccountWithFullInfo(*info, *options);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Failed to write result");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcUpdateOsAccountWithFullInfo(MessageParcel &data, MessageParcel &reply)
{
    std::shared_ptr<OsAccountInfo> info(data.ReadParcelable<OsAccountInfo>());
    if (info == nullptr) {
        ACCOUNT_LOGE("Failed to read OsAccountInfo");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }

    ErrCode code = info->ParamCheck();
    if (code != ERR_OK) {
        ACCOUNT_LOGE("OsAccountInfo required field is invalidate");
        return code;
    }

    ErrCode result = UpdateOsAccountWithFullInfo(*info);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Failed to write result");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcCreateOsAccountForDomain(MessageParcel &data, MessageParcel &reply)
{
    ACCOUNT_LOGI("Calling uid: %{public}d, pid: %{public}d",
        IPCSkeleton::GetCallingUid(), IPCSkeleton::GetCallingRealPid());
    OsAccountType type = static_cast<OsAccountType>(data.ReadInt32());
    std::shared_ptr<DomainAccountInfo> info(data.ReadParcelable<DomainAccountInfo>());
    if (info == nullptr) {
        ACCOUNT_LOGE("Failed to read domain account info");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }

    if (info->domain_.empty() || info->domain_.size() > Constants::DOMAIN_NAME_MAX_SIZE) {
        ACCOUNT_LOGE("Read invalid domain length %{public}zu.", info->domain_.size());
        reply.WriteInt32(ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
        return ERR_NONE;
    }

    if (info->accountName_.empty() || info->accountName_.size() > Constants::LOCAL_NAME_MAX_SIZE) {
        ACCOUNT_LOGE("Read invalid domain account name length %{public}zu.", info->accountName_.size());
        reply.WriteInt32(ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
        return ERR_NONE;
    }

    OsAccountInfo osAccountInfo;
    auto callback = iface_cast<IDomainAccountCallback>(data.ReadRemoteObject());
    if (callback == nullptr) {
        ACCOUNT_LOGE("Failed to read parcel");
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
    ACCOUNT_LOGI("Calling uid: %{public}d, pid: %{public}d",
        IPCSkeleton::GetCallingUid(), IPCSkeleton::GetCallingRealPid());
    int32_t localId;
    if (!data.ReadInt32(localId)) {
        ACCOUNT_LOGE("Failed to read localId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }

    ErrCode result = RemoveOsAccount(localId);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcSetOsAccountName(MessageParcel &data, MessageParcel &reply)
{
    int32_t localId;
    if (!data.ReadInt32(localId)) {
        ACCOUNT_LOGE("Failed to read localId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    std::string localName = data.ReadString();
    ErrCode result = SetOsAccountName(localId, localName);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcSetOsAccountConstraints(MessageParcel &data, MessageParcel &reply)
{
    int32_t localId;
    if (!data.ReadInt32(localId)) {
        ACCOUNT_LOGE("Failed to read localId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    std::vector<std::string> constraints;
    bool stringVectorReadSuccess = data.ReadStringVector(&constraints);
    if (!stringVectorReadSuccess) {
        ACCOUNT_LOGE("Failed to read StringVector for constraints");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    bool enable = data.ReadBool();
    ErrCode result = SetOsAccountConstraints(localId, constraints, enable);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcSetOsAccountProfilePhoto(MessageParcel &data, MessageParcel &reply)
{
    int32_t localId;
    if (!data.ReadInt32(localId)) {
        ACCOUNT_LOGE("Failed to read localId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }

    int32_t photoSize;
    if (!data.ReadInt32(photoSize)) {
        ACCOUNT_LOGE("Failed to read photoSize");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }

    if (photoSize - 1 > static_cast<int32_t>(Constants::LOCAL_PHOTO_MAX_SIZE) || photoSize < 1) {
        ACCOUNT_LOGE("PhotoSize is invalid, photosize = %{public}d", photoSize);
        return ERR_ACCOUNT_COMMON_INVALID_PARAMETER;
    }
    auto readRawData = data.ReadRawData(photoSize);
    if (readRawData == nullptr) {
        ACCOUNT_LOGE("Failed to read photoData");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    const char *photoData = reinterpret_cast<const char *>(readRawData);
    std::string photo = std::string(photoData, photoSize - 1);
    ErrCode result = SetOsAccountProfilePhoto(localId, photo);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcQueryOsAccountById(MessageParcel &data, MessageParcel &reply)
{
    int32_t localId;
    if (!data.ReadInt32(localId)) {
        ACCOUNT_LOGE("Failed to read localId");
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
        ACCOUNT_LOGE("Failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!WriteOsAccountInfoList(osAccountInfos, reply)) {
        ACCOUNT_LOGE("Failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcQueryMaxOsAccountNumber(MessageParcel &data, MessageParcel &reply)
{
    uint32_t maxOsAccountNumber = 0;
    ErrCode result = QueryMaxOsAccountNumber(maxOsAccountNumber);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteUint32(maxOsAccountNumber)) {
        ACCOUNT_LOGE("Failed to write reply");
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
        ACCOUNT_LOGE("Failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteUint32(osAccountsCount)) {
        ACCOUNT_LOGE("Failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcGetOsAccountAllConstraints(MessageParcel &data, MessageParcel &reply)
{
    int32_t localId;
    if (!data.ReadInt32(localId)) {
        ACCOUNT_LOGE("Failed to read localId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    std::vector<std::string> constraints;
    ErrCode result = GetOsAccountAllConstraints(localId, constraints);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteStringVector(constraints)) {
        ACCOUNT_LOGE("Failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcGetOsAccountLocalIdFromProcess(MessageParcel &data, MessageParcel &reply)
{
    int localId = -1;
#ifdef HICOLLIE_ENABLE
    unsigned int flag = HiviewDFX::XCOLLIE_FLAG_LOG | HiviewDFX::XCOLLIE_FLAG_RECOVERY;
    XCollieCallback callbackFunc = [](void *) {
        ACCOUNT_LOGE("ProcGetOsAccountLocalIdFromProcess failed due to timeout.");
        ReportOsAccountOperationFail(IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR,
            "watchDog", -1, "Get osaccount local id time out");
    };
    int timerId = HiviewDFX::XCollie::GetInstance().SetTimer(
        TIMER_NAME, RECOVERY_TIMEOUT, callbackFunc, nullptr, flag);
#endif // HICOLLIE_ENABLE
    ErrCode result = GetOsAccountLocalIdFromProcess(localId);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Failed to write reply, result %{public}d.", result);
#ifdef HICOLLIE_ENABLE
        HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
#endif // HICOLLIE_ENABLE
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteInt32(localId)) {
        ACCOUNT_LOGE("Failed to write reply");
#ifdef HICOLLIE_ENABLE
        HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
#endif // HICOLLIE_ENABLE
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
#ifdef HICOLLIE_ENABLE
        HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
#endif // HICOLLIE_ENABLE
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcIsMainOsAccount(MessageParcel &data, MessageParcel &reply)
{
    bool isMainOsAccount = false;
    ErrCode result = IsMainOsAccount(isMainOsAccount);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteBool(isMainOsAccount)) {
        ACCOUNT_LOGE("Failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcGetOsAccountProfilePhoto(MessageParcel &data, MessageParcel &reply)
{
    int32_t localId;
    if (!data.ReadInt32(localId)) {
        ACCOUNT_LOGE("Failed to read localId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    std::string photo;
    ErrCode result = GetOsAccountProfilePhoto(localId, photo);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteInt32(photo.size() + 1)) {
        ACCOUNT_LOGE("Failed to write photo");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteRawData(photo.c_str(), photo.size() + 1)) {
        ACCOUNT_LOGE("Failed to write photo");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcGetOsAccountLocalIdFromDomain(MessageParcel &data, MessageParcel &reply)
{
    std::string domain = data.ReadString();
    std::string domainAccountName = data.ReadString();
    if (domain.empty() || domain.size() > Constants::DOMAIN_NAME_MAX_SIZE) {
        ACCOUNT_LOGE("Failed to read string for domain name. length %{public}zu.", domain.size());
        reply.WriteInt32(ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
        return ERR_NONE;
    }

    if (domainAccountName.empty() || domainAccountName.size() > Constants::LOCAL_NAME_MAX_SIZE) {
        ACCOUNT_LOGE("Failed to read string for domainAccountName. length %{public}zu.", domainAccountName.size());
        reply.WriteInt32(ERR_ACCOUNT_COMMON_INVALID_PARAMETER);
        return ERR_NONE;
    }

    int localId = -1;
    DomainAccountInfo domainInfo(domain, domainAccountName);
    ErrCode result = GetOsAccountLocalIdFromDomain(domainInfo, localId);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteInt32(localId)) {
        ACCOUNT_LOGE("Failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcGetOsAccountTypeFromProcess(MessageParcel &data, MessageParcel &reply)
{
    OsAccountType type = OsAccountType::ADMIN;
    ErrCode result = GetOsAccountTypeFromProcess(type);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteInt32(static_cast<int32_t>(type))) {
        ACCOUNT_LOGE("Failed to write reply");
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
        ACCOUNT_LOGE("Failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteInt32(id)) {
        ACCOUNT_LOGE("Failed to write reply");
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
        ACCOUNT_LOGE("Failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteInt64(serialNumber)) {
        ACCOUNT_LOGE("Failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcIsOsAccountActived(MessageParcel &data, MessageParcel &reply)
{
    int32_t localId;
    if (!data.ReadInt32(localId)) {
        ACCOUNT_LOGE("Failed to read localId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    bool isOsAccountActived = false;
    ErrCode result = IsOsAccountActived(localId, isOsAccountActived);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteBool(isOsAccountActived)) {
        ACCOUNT_LOGE("Failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcCheckOsAccountConstraintEnabled(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    int32_t localId;
    if (!data.ReadInt32(localId)) {
        ACCOUNT_LOGE("Failed to read localId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    std::string constraint = data.ReadString();
    if (constraint.empty() || constraint.size() > Constants::CONSTRAINT_MAX_SIZE) {
        ACCOUNT_LOGE("Failed to read string for constraint. length %{public}zu.", constraint.size());
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
        ACCOUNT_LOGE("Stub code is invalid");
        return IPC_INVOKER_ERR;
    }
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteBool(isEnabled)) {
        ACCOUNT_LOGE("Failed to write reply");
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
        ACCOUNT_LOGE("Failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteBool(isMultiOsAccountEnable)) {
        ACCOUNT_LOGE("Failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcIsOsAccountVerified(MessageParcel &data, MessageParcel &reply)
{
    int32_t localId;
    if (!data.ReadInt32(localId)) {
        ACCOUNT_LOGE("Failed to read localId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    bool isVerified = false;
    ErrCode result = IsOsAccountVerified(localId, isVerified);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteBool(isVerified)) {
        ACCOUNT_LOGE("Failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcIsOsAccountDeactivating(MessageParcel &data, MessageParcel &reply)
{
    int32_t localId;
    if (!data.ReadInt32(localId)) {
        ACCOUNT_LOGE("Failed to read localId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    bool isDeactivating = false;
    ErrCode result = IsOsAccountDeactivating(localId, isDeactivating);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Failed to write result.");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (result != ERR_OK) {
        ACCOUNT_LOGE("Failed to get deactivate status, result %{public}d.", result);
        return ERR_OK;
    }
    if (!reply.WriteBool(isDeactivating)) {
        ACCOUNT_LOGE("Failed to write deactivate status.");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode OsAccountStub::ProcIsOsAccountExists(MessageParcel &data, MessageParcel &reply)
{
    int32_t localId;
    if (!data.ReadInt32(localId)) {
        ACCOUNT_LOGE("Failed to read localId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    bool isOsAccountExists = false;
    ErrCode result = IsOsAccountExists(localId, isOsAccountExists);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteBool(isOsAccountExists)) {
        ACCOUNT_LOGE("Failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcSubscribeOsAccount(MessageParcel &data, MessageParcel &reply)
{
#ifdef HICOLLIE_ENABLE
    unsigned int flag = HiviewDFX::XCOLLIE_FLAG_LOG | HiviewDFX::XCOLLIE_FLAG_RECOVERY;
    XCollieCallback callbackFunc = [](void *) {
        ACCOUNT_LOGE("ProcSubscribeOsAccount failed due to timeout.");
        ReportOsAccountOperationFail(IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR,
            "watchDog", -1, "Subscribe osaccount time out");
    };
    int timerId = HiviewDFX::XCollie::GetInstance().SetTimer(
        TIMER_NAME, RECOVERY_TIMEOUT, callbackFunc, nullptr, flag);
#endif // HICOLLIE_ENABLE
    std::unique_ptr<OsAccountSubscribeInfo> subscribeInfo(data.ReadParcelable<OsAccountSubscribeInfo>());
    if (!subscribeInfo) {
        ACCOUNT_LOGE("Failed to read parcelable for subscribeInfo");
#ifdef HICOLLIE_ENABLE
        HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
#endif // HICOLLIE_ENABLE
        return IPC_STUB_INVALID_DATA_ERR;
    }

    sptr<IRemoteObject> eventListener = data.ReadRemoteObject();
    if (eventListener == nullptr) {
        ACCOUNT_LOGE("Failed to read remote object for eventListener");
#ifdef HICOLLIE_ENABLE
        HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
#endif // HICOLLIE_ENABLE
        return IPC_STUB_INVALID_DATA_ERR;
    }

    ErrCode result = SubscribeOsAccount(*subscribeInfo, eventListener);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Failed to write reply, result %{public}d.", result);
#ifdef HICOLLIE_ENABLE
        HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
#endif // HICOLLIE_ENABLE
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
#ifdef HICOLLIE_ENABLE
        HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
#endif // HICOLLIE_ENABLE
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcUnsubscribeOsAccount(MessageParcel &data, MessageParcel &reply)
{
    sptr<IRemoteObject> eventListener = data.ReadRemoteObject();
    if (eventListener == nullptr) {
        ACCOUNT_LOGE("Failed to read remote object for eventListener");
        return IPC_STUB_INVALID_DATA_ERR;
    }

    ErrCode result = UnsubscribeOsAccount(eventListener);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcActivateOsAccount(MessageParcel &data, MessageParcel &reply)
{
    ACCOUNT_LOGI("Calling uid: %{public}d, pid: %{public}d",
        IPCSkeleton::GetCallingUid(), IPCSkeleton::GetCallingRealPid());
    int32_t localId;
    if (!data.ReadInt32(localId)) {
        ACCOUNT_LOGE("Failed to read localId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    StartTraceAdapter("AccountManager ActivateAccount");
    ErrCode result = ActivateOsAccount(localId);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Failed to write reply, result %{public}d.", result);
        FinishTraceAdapter();
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    FinishTraceAdapter();
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcDeactivateOsAccount(MessageParcel &data, MessageParcel &reply)
{
    ACCOUNT_LOGI("Calling uid: %{public}d, pid: %{public}d",
        IPCSkeleton::GetCallingUid(), IPCSkeleton::GetCallingRealPid());
    int32_t localId;
    if (!data.ReadInt32(localId)) {
        ACCOUNT_LOGE("Failed to read localId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    ErrCode result = DeactivateOsAccount(localId);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Failed to write reply, result %{public}d.", result);
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
        ACCOUNT_LOGE("Failed to read localId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    ErrCode result = StartOsAccount(localId);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcGetOsAccountSwitchMod(MessageParcel &data, MessageParcel &reply)
{
    OS_ACCOUNT_SWITCH_MOD osAccountSwitchMod = GetOsAccountSwitchMod();
    if (!reply.WriteInt32(osAccountSwitchMod)) {
        ACCOUNT_LOGE("Failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcIsCurrentOsAccountVerified(MessageParcel &data, MessageParcel &reply)
{
    bool isVerified = false;
    ErrCode result = IsCurrentOsAccountVerified(isVerified);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteBool(isVerified)) {
        ACCOUNT_LOGE("Failed to write reply isVerified.");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcIsOsAccountCompleted(MessageParcel &data, MessageParcel &reply)
{
    int32_t localId;
    if (!data.ReadInt32(localId)) {
        ACCOUNT_LOGE("Failed to read localId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    bool isOsAccountCompleted = false;
    ErrCode result = IsOsAccountCompleted(localId, isOsAccountCompleted);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteBool(isOsAccountCompleted)) {
        ACCOUNT_LOGE("Failed to write reply isOsAccountCompleted.");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcSetCurrentOsAccountIsVerified(MessageParcel &data, MessageParcel &reply)
{
    bool isVerified = data.ReadBool();
    ErrCode result = SetCurrentOsAccountIsVerified(isVerified);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcSetOsAccountIsVerified(MessageParcel &data, MessageParcel &reply)
{
    int32_t localId;
    if (!data.ReadInt32(localId)) {
        ACCOUNT_LOGE("Failed to read localId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    bool isVerified = data.ReadBool();
    ErrCode result = SetOsAccountIsVerified(localId, isVerified);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Failed to write reply, result %{public}d.", result);
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
        ACCOUNT_LOGE("Failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }

    if (!reply.WriteUint32(state.size())) {
        ACCOUNT_LOGE("Failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }

    for (auto info : state) {
        if (!reply.WriteString(info)) {
            ACCOUNT_LOGE("Failed to write reply");
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
        ACCOUNT_LOGE("Failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteInt32(createdOsAccountNum)) {
        ACCOUNT_LOGE("Failed to write reply");
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
        ACCOUNT_LOGE("Failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteInt64(serialNumber)) {
        ACCOUNT_LOGE("Failed to write reply");
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
        ACCOUNT_LOGE("Failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteInt32(id)) {
        ACCOUNT_LOGE("Failed to write reply");
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
        ACCOUNT_LOGE("Failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!WriteOsAccountInfoList(osAccountList, reply)) {
        ACCOUNT_LOGE("ProcGetOsAccountListFromDatabase osAccountInfos failed stub");
        ACCOUNT_LOGE("Failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcQueryActiveOsAccountIds(MessageParcel &data, MessageParcel &reply)
{
    std::vector<int32_t> ids;
#ifdef HICOLLIE_ENABLE
    unsigned int flag = HiviewDFX::XCOLLIE_FLAG_LOG | HiviewDFX::XCOLLIE_FLAG_RECOVERY;
    XCollieCallback callbackFunc = [](void *) {
        ACCOUNT_LOGE("ProcQueryActiveOsAccountIds failed due to timeout.");
        ReportOsAccountOperationFail(IPCSkeleton::GetCallingUid() / UID_TRANSFORM_DIVISOR,
            "watchDog", -1, "Query active account id time out");
    };
    int timerId = HiviewDFX::XCollie::GetInstance().SetTimer(
        TIMER_NAME, RECOVERY_TIMEOUT, callbackFunc, nullptr, flag);
#endif // HICOLLIE_ENABLE
    ErrCode result = QueryActiveOsAccountIds(ids);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Failed to write reply, result %{public}d.", result);
#ifdef HICOLLIE_ENABLE
        HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
#endif // HICOLLIE_ENABLE
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteInt32Vector(ids)) {
        ACCOUNT_LOGE("Failed to write active list");
#ifdef HICOLLIE_ENABLE
        HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
#endif // HICOLLIE_ENABLE
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
#ifdef HICOLLIE_ENABLE
        HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
#endif // HICOLLIE_ENABLE
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcQueryOsAccountConstraintSourceTypes(MessageParcel &data, MessageParcel &reply)
{
    int32_t localId;
    if (!data.ReadInt32(localId)) {
        ACCOUNT_LOGE("Failed to read localId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    std::string constraint;
    if (!data.ReadString(constraint)) {
        ACCOUNT_LOGE("Failed to read constraint");
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
            ACCOUNT_LOGE("Failed to write reply");
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
        ACCOUNT_LOGE("Failed to read StringVector for constraints");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    bool enable = data.ReadBool();
    int enforcerId = data.ReadInt32();
    if (enforcerId < 0) {
        ACCOUNT_LOGE("Failed to read int for localId");
        reply.WriteInt32(ERR_OSACCOUNT_KIT_READ_IN_LOCAL_ID_ERROR);
        return ERR_NONE;
    }
    bool isDeviceOwner = data.ReadBool();
    ErrCode result = SetGlobalOsAccountConstraints(constraints, enable, enforcerId, isDeviceOwner);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcSetDefaultActivatedOsAccount(MessageParcel &data, MessageParcel &reply)
{
    int32_t localId;
    if (!data.ReadInt32(localId)) {
        ACCOUNT_LOGE("Failed to read localId");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    ErrCode result = SetDefaultActivatedOsAccount(localId);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcGetDefaultActivatedOsAccount(MessageParcel &data, MessageParcel &reply)
{
    int32_t localId = 0;
    ErrCode result = GetDefaultActivatedOsAccount(localId);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteInt32(localId)) {
        ACCOUNT_LOGE("Failed to write reply");
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    return ERR_NONE;
}

ErrCode OsAccountStub::ProcGetOsAccountShortName(MessageParcel &data, MessageParcel &reply)
{
    std::string shortName;
    ErrCode result = GetOsAccountShortName(shortName);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Failed to write reply, result %{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (!reply.WriteString(shortName)) {
        ACCOUNT_LOGE("Failed to write reply");
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

ErrCode OsAccountStub::ProcGetOsAccountNameById(MessageParcel &data, MessageParcel &reply)
{
    int32_t id;
    if (!data.ReadInt32(id)) {
        ACCOUNT_LOGE("Read id failed.");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    std::string name;
    ErrCode result = GetOsAccountNameById(id, name);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Failed to write result, result=%{public}d.", result);
        return IPC_STUB_WRITE_PARCEL_ERR;
    }
    if (result != ERR_OK) {
        return ERR_NONE;
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
        ACCOUNT_LOGE("Failed to read StringVector for constraints");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    bool enable = data.ReadBool();
    int targetId = data.ReadInt32();
    if (targetId < 0) {
        ACCOUNT_LOGE("Failed to read int for targetId");
        reply.WriteInt32(ERR_OSACCOUNT_KIT_READ_IN_LOCAL_ID_ERROR);
        return ERR_NONE;
    }
    int enforcerId = data.ReadInt32();
    if (enforcerId < 0) {
        ACCOUNT_LOGE("Failed to read int for enforcerId");
        reply.WriteInt32(ERR_OSACCOUNT_KIT_READ_IN_LOCAL_ID_ERROR);
        return ERR_NONE;
    }
    bool isDeviceOwner = data.ReadBool();
    ErrCode result = SetSpecificOsAccountConstraints(constraints, enable, targetId, enforcerId, isDeviceOwner);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Failed to write reply");
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

ErrCode OsAccountStub::ProcGetOsAccountDomainInfo(MessageParcel &data, MessageParcel &reply)
{
    int32_t localId;
    if (!data.ReadInt32(localId)) {
        ACCOUNT_LOGE("Read localId failed.");
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    DomainAccountInfo domainInfo;
    ErrCode result = GetOsAccountDomainInfo(localId, domainInfo);
    if (!reply.WriteInt32(result)) {
        ACCOUNT_LOGE("Write result failed.");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    if (result != ERR_OK) {
        return result;
    }
    if (!reply.WriteParcelable(&domainInfo)) {
        ACCOUNT_LOGE("Write domainAccountInfo failed.");
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    return ERR_NONE;
}
}  // namespace AccountSA
}  // namespace OHOS
