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

#include "mock_json_util.h"

namespace OHOS {
namespace AccountSA {
static int32_t g_times = 0;
static int32_t g_falseTime = 0;
static std::string g_methodName = "";
void SetTimes(int32_t times, int32_t falseTime, std::string methodName)
{
    g_times = times;
    g_falseTime = falseTime;
    g_methodName = methodName;
}
bool MockMothd()
{
    g_times++;
    if (g_times == g_falseTime) {
        return false;
    }
    return true;
}

bool AddVectorStringToJson(CJsonUnique &jsonObj, const std::string &key, const std::vector<std::string> &vec)
{
    if (g_methodName != "AddVectorStringToJson") {
        return true;
    }
    return MockMothd();
}

bool AddVectorStringToJson(CJson *jsonObj, const std::string &key, const std::vector<std::string> &vec)
{
    if (g_methodName != "AddVectorStringToJson") {
        return true;
    }
    return MockMothd();
}

bool AddObjToJson(CJsonUnique &jsonObj, const std::string &key, CJsonUnique &childObj)
{
    if (g_methodName != "AddObjToJson") {
        return true;
    }
    return MockMothd();
}

bool AddObjToJson(CJson *jsonObj, const std::string &key, const CJson *childObj)
{
    if (g_methodName != "AddObjToJson") {
        return true;
    }
    return MockMothd();
}
} // namespace AccountSA
} // namespace OHOS