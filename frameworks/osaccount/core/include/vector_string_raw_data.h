/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_FRAMEWORKS_OSACCOUNT_CORE_INCLUDE_VECTOR_STRING_RAW_DATA_H
#define OS_ACCOUNT_FRAMEWORKS_OSACCOUNT_CORE_INCLUDE_VECTOR_STRING_RAW_DATA_H

#include "ipc_types.h"
#include <sstream>

namespace OHOS {
namespace AccountSA {
struct VectorStringRawData {
    uint32_t size;
    const void* data;
    std::string serializedData;

    ErrCode Marshalling(const std::vector<std::string>& in)
    {
        std::stringstream ss;
        uint32_t stringVecSize = in.size();
        ss.write(reinterpret_cast<const char*>(&stringVecSize), sizeof(stringVecSize));
        for (const auto& str : in) {
            uint32_t strLength = str.length();
            ss.write(reinterpret_cast<const char*>(&strLength), sizeof(strLength));
            ss.write(str.c_str(), strLength);
        }
        serializedData = ss.str();
        data = reinterpret_cast<const void*>(serializedData.data());
        size = serializedData.length();
        return ERR_OK;
    }

    ErrCode Unmarshalling(std::vector<std::string>& out) const
    {
        std::stringstream ss;
        ss.write(reinterpret_cast<const char*>(data), size);
        uint32_t ssLength = static_cast<uint32_t>(ss.tellp());
        uint32_t stringVecSize = 0;
        ss.read(reinterpret_cast<char*>(&stringVecSize), sizeof(stringVecSize));
        for (uint32_t i = 0; i < stringVecSize; ++i) {
            uint32_t strLength = 0;
            ss.read(reinterpret_cast<char*>(&strLength), sizeof(strLength));
            if (strLength > ssLength - static_cast<uint32_t>(ss.tellg())) {
                return ERR_INVALID_DATA;
            }
            std::string str;
            str.resize(strLength);
            ss.read(&str[0], strLength);
            out.emplace_back(std::move(str));
        }
        return ERR_OK;
    }

    int32_t RawDataCpy(const void* inData)
    {
        std::stringstream ss;
        ss.write(reinterpret_cast<const char *>(inData), size);
        serializedData = ss.str();
        data = reinterpret_cast<const void *>(serializedData.data());
        return ERR_OK;
    }
};
}  // namespace AccountSA
}  // namespace OHOS

#endif  // OS_ACCOUNT_FRAMEWORKS_OSACCOUNT_CORE_INCLUDE_VECTOR_STRING_RAW_DATA_H
