/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ACCOUNT_TAIHE_COMMON_H
#define ACCOUNT_TAIHE_COMMON_H

#include "accesstoken_kit.h"
#include "ohos.account.osAccount.proj.hpp"
#include "ohos.account.osAccount.impl.hpp"
#include "taihe/runtime.hpp"
#include "taihe/string.hpp"
#include "os_account_info.h"
#include "ipc_skeleton.h"
#include "tokenid_kit.h"
#include "account_error_no.h"


using namespace taihe;
using namespace ohos::account::osAccount;
using TaiheOsAccountType = ohos::account::osAccount::OsAccountType;
using TaiheOsAccountInfo = ohos::account::osAccount::OsAccountInfo;
using TaiheCreateOsAccountOptions = ohos::account::osAccount::CreateOsAccountOptions;
using TaiheCredentialInfo = ohos::account::osAccount::CredentialInfo;
using TaiheAuthType = ohos::account::osAccount::AuthType;
using TaiheIInputer = ohos::account::osAccount::IInputer;
using TaiheOsAccountSwitchEventData = ohos::account::osAccount::OsAccountSwitchEventData;
using TaiheIInputData = ohos::account::osAccount::IInputData;
using TaiheCredentialChangeType = ohos::account::osAccount::CredentialChangeType;
using TaiheCredentialChangeInfo = ohos::account::osAccount::CredentialChangeInfo;

namespace OHOS {
namespace AccountSA {
bool IsAccountIdValid(int32_t accountId);
bool IsSystemApp();
bool CheckPermission(const std::string &permissionName);
}
}
#endif // ACCOUNT_TAIHE_COMMON_H