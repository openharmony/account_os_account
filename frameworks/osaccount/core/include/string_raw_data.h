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

#ifndef OS_ACCOUNT_FRAMEWORKS_OSACCOUNT_CORE_INCLUDE_STRING_RAW_DATA_H
#define OS_ACCOUNT_FRAMEWORKS_OSACCOUNT_CORE_INCLUDE_STRING_RAW_DATA_H

#include "ipc_types.h"
#include <sstream>

namespace OHOS {
namespace AccountSA {
struct StringRawData {
    uint32_t size;
    const void* data;
    std::string serializedData;

    ErrCode Marshalling(const std::string& in)
    {
        std::stringstream ss;
        uint32_t length = in.length();
        ss.write(reinterpret_cast<const char*>(&length), sizeof(length));
        ss.write(in.c_str(), length);
        serializedData = ss.str();
        data = reinterpret_cast<const void*>(serializedData.data());
        size = serializedData.length();
        return ERR_OK;
    }

    ErrCode Unmarshalling(std::string& out) const
    {
        std::stringstream ss;
        ss.write(reinterpret_cast<const char*>(data), size);
        uint32_t length = 0;
        ss.read(reinterpret_cast<char*>(&length), sizeof(length));
        out.resize(length);
        ss.read(&out[0], length);
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

#endif  // OS_ACCOUNT_FRAMEWORKS_OSACCOUNT_CORE_INCLUDE_STRING_RAW_DATA_H
