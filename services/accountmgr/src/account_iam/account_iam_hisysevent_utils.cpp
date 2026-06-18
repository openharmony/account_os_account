/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "account_iam_hisysevent_utils.h"

namespace OHOS {
namespace AccountSA {
namespace {
// DELIMITER
const char IAM_HISYSEVENT_DELIMITER[] = "_";
}

std::string ConstructSubOperationStr(const char* mainOperation, const char* subOperation)
{
    return std::string(mainOperation) + IAM_HISYSEVENT_DELIMITER + std::string(subOperation);
}

std::string ConstructSubOperationStr(const char* mainOperation, const int32_t authType)
{
    return std::string(mainOperation) + IAM_HISYSEVENT_DELIMITER + std::to_string(authType);
}

std::string ConstructSubOperationStr(const char* mainOperation, const char* subOperation, const int32_t authType)
{
    return std::string(mainOperation) + IAM_HISYSEVENT_DELIMITER + std::string(subOperation) +
        IAM_HISYSEVENT_DELIMITER + std::to_string(authType);
}
} // namespace AccountSA
} // namespace OHOS
