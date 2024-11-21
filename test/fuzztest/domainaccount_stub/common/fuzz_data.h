/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef FUZZ_DATA_H
#define FUZZ_DATA_H
#include <string>
#include "securec.h"

namespace OHOS {
using namespace std;
namespace {
static constexpr uint32_t BOOL_MODULO_NUM = 2;
}
class FuzzData {
public:
    explicit FuzzData(const uint8_t *data, const size_t size)
        :pos_(0), data_(data), size_(size) {}

    template <class T> T GetData()
    {
        T object{};
        size_t objectSize = sizeof(object);
        if (data_ == nullptr || objectSize > size_ - pos_) {
            return object;
        }
        errno_t ret = memcpy_s(&object, objectSize, data_ + pos_, objectSize);
        if (ret != EOK) {
            return {};
        }
        pos_ += objectSize;
        return object;
    }

    std::string GetStringFromData(size_t pos, size_t strlen)
    {
        if (pos > size_) {
            return "test";
        }
        char cstr[strlen + 1];
        cstr[strlen] = '\0';
        pos_ = pos;
        for (size_t i = 0; i < strlen; i++) {
            char tmp = GetData<char>();
            if (tmp == '\0') {
                tmp = '1';
            }
            cstr[i] = tmp;
        }
        std::string str(cstr);
        return str;
    }

    std::string GenerateString()
    {
        return GetStringFromData(0, (GetData<uint32_t>() % size_));
    }

    template <class T> T GenerateEnmu(T enmuMax)
    {
        return static_cast<T>(GetData<uint32_t>() % (static_cast<uint32_t>(enmuMax) + 1));
    }

    bool GenerateBool()
    {
        return (GetData<uint32_t>() % BOOL_MODULO_NUM) == 0;
    }

public:
    size_t pos_;

private:
    const uint8_t *data_;
    const size_t size_;
};
} // OHOS
#endif // FUZZ_DATA_H