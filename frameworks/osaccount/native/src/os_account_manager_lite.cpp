/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "os_account_manager_lite.h"

#include "errors.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "message_option.h"
#include "message_parcel.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AccountSA {
namespace {
const std::u16string ACCOUNT_DESCRIPTOR = u"ohos.accountfwk.IAccount";
const std::u16string OS_ACCOUNT_DESCRIPTOR = u"ohos.accountfwk.IOsAccount";
constexpr uint32_t COMMAND_GET_OS_ACCOUNT_SERVICE = 14;
constexpr uint32_t COMMAND_GET_FOREGROUND_OS_ACCOUNT_LOCAL_ID_OUT_INT = 77;

ErrCode ConvertToAccountErrCode(ErrCode idlErrCode)
{
    if (idlErrCode == ERR_INVALID_VALUE) {
        return ERR_ACCOUNT_COMMON_WRITE_DESCRIPTOR_ERROR;
    }
    if (idlErrCode == ERR_INVALID_DATA) {
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    return idlErrCode;
}

sptr<IRemoteObject> GetOsAccountService()
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        return nullptr;
    }

    auto accountMgrService = samgr->GetSystemAbility(SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN);
    if (accountMgrService == nullptr) {
        return nullptr;
    }

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(ACCOUNT_DESCRIPTOR)) {
        return nullptr;
    }
    if (accountMgrService->SendRequest(COMMAND_GET_OS_ACCOUNT_SERVICE, data, reply, option) != ERR_NONE) {
        return nullptr;
    }

    ErrCode result = ERR_OK;
    if (!reply.ReadInt32(result)) {
        return nullptr;
    }
    if (result != ERR_OK) {
        return nullptr;
    }
    return reply.ReadRemoteObject();
}
}  // namespace

ErrCode OsAccountManagerLite::GetForegroundOsAccountLocalId(int32_t &localId)
{
    auto osAccountService = GetOsAccountService();
    if (osAccountService == nullptr) {
        return ERR_ACCOUNT_COMMON_GET_PROXY;
    }

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(OS_ACCOUNT_DESCRIPTOR)) {
        return ERR_ACCOUNT_COMMON_WRITE_PARCEL_ERROR;
    }
    ErrCode errCode = osAccountService->SendRequest(
        COMMAND_GET_FOREGROUND_OS_ACCOUNT_LOCAL_ID_OUT_INT, data, reply, option);
    if (errCode != ERR_NONE) {
        return ERR_ACCOUNT_COMMON_REMOTE_DIED;
    }

    if (!reply.ReadInt32(errCode)) {
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    if (errCode != ERR_OK) {
        return ConvertToAccountErrCode(errCode);
    }
    if (!reply.ReadInt32(localId)) {
        return ERR_ACCOUNT_COMMON_READ_PARCEL_ERROR;
    }
    return ERR_OK;
}
}  // namespace AccountSA
}  // namespace OHOS
