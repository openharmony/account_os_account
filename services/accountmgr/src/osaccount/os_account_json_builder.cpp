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

#include "os_account_json_builder.h"

namespace OHOS {
namespace AccountSA {

CJsonUnique BuildAccountListJson(const std::vector<std::string> &accounts)
{
    auto defaultActivatedIds = CreateJson();
    AddIntToJson(defaultActivatedIds, std::to_string(Constants::DEFAULT_DISPLAY_ID), Constants::START_USER_ID);
    auto accountList = CreateJson();
    AddVectorStringToJson(accountList, Constants::ACCOUNT_LIST, accounts);
    AddIntToJson(accountList, Constants::COUNT_ACCOUNT_NUM, accounts.size());
    AddObjToJson(accountList, DEFAULT_ACTIVATED_ACCOUNT_ID, defaultActivatedIds);
    AddIntToJson(accountList, Constants::MAX_ALLOW_CREATE_ACCOUNT_ID, Constants::MAX_USER_ID);
    AddInt64ToJson(accountList, Constants::SERIAL_NUMBER_NUM, Constants::SERIAL_NUMBER_NUM_START);
    AddBoolToJson(accountList, IS_SERIAL_NUMBER_FULL, Constants::IS_SERIAL_NUMBER_FULL_INIT_VALUE);
    AddIntToJson(accountList, NEXT_LOCAL_ID, Constants::START_USER_ID + 1);
    return accountList;
}
}  // namespace AccountSA
}  // namespace OHOS
