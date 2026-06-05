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
#ifndef OS_ACCOUNT_FRAMEWORK_SUB_PROFILE_CONTEXT_H
#define OS_ACCOUNT_FRAMEWORK_SUB_PROFILE_CONTEXT_H

#include <map>
#include <vector>
#include <stdint.h>

namespace OHOS {
namespace AccountSA {
#ifdef ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE

constexpr int32_t OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER = 1000;
constexpr int32_t HEADLESS_SUBPROFILE_INDEX = 0;

struct SubProfileContext {
    int32_t nextSubProfileId = 0;
    std::vector<int32_t> subProfileIdList;
    int32_t nextSubProfileIndex = 0;
    std::map<int32_t, int32_t> subProfileIndexMap;

    SubProfileContext() = default;
    explicit SubProfileContext(int32_t nextId, const std::vector<int32_t> &idList,
        int32_t nextIndex, const std::map<int32_t, int32_t> &indexMap)
        : nextSubProfileId(nextId), subProfileIdList(idList),
          nextSubProfileIndex(nextIndex), subProfileIndexMap(indexMap) {}

    static SubProfileContext CreateWithHeadlessDefault(int32_t osAccountId)
    {
        int32_t baseSubProfileId = osAccountId * OS_ACCOUNT_SUBSPACE_ID_MULTIPLIER;
        SubProfileContext ctx;
        ctx.subProfileIndexMap[HEADLESS_SUBPROFILE_INDEX] = baseSubProfileId;
        ctx.subProfileIdList.push_back(baseSubProfileId);
        ctx.nextSubProfileId = baseSubProfileId + 1;
        ctx.nextSubProfileIndex = 1;
        return ctx;
    }
};
#endif // ENABLE_MULTIPLE_OS_ACCOUNT_SUBSPACE
} // namespace AccountSA
} // namespace OHOS

#endif // OS_ACCOUNT_FRAMEWORK_SUB_PROFILE_CONTEXT_H