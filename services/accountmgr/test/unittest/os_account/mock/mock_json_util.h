/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_MOCK_JSON_UTILS_H
#define OS_ACCOUNT_MOCK_JSON_UTILS_H

#include <map>
#include <memory>
#include <vector>
#include <string>
#include <set>
#include <functional>
#include "cJSON.h"

namespace OHOS {
namespace AccountSA {
typedef cJSON CJson;
typedef std::unique_ptr<CJson, std::function<void(CJson *ptr)>> CJsonUnique;
void SetTimes(int32_t times, int32_t falseTime, std::string methodName);
bool AddVectorStringToJson(CJsonUnique &jsonObj, const std::string &key, const std::vector<std::string> &vec);
bool AddVectorStringToJson(CJson *jsonObj, const std::string &key, const std::vector<std::string> &vec);
bool AddObjToJson(CJsonUnique &jsonObj, const std::string &key, CJsonUnique &childObj);
bool AddObjToJson(CJson *jsonObj, const std::string &key, const CJson *childObj);
} // namespace AccountSA
} // namespace OHOS
#endif // OS_ACCOUNT_MOCK_JSON_UTILS_H