/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "os_account_photo_operator.h"

#include "account_log_wrapper.h"

namespace OHOS {
namespace AccountSA {
namespace {
const size_t SIZET_ZERO = 0;
const size_t SIZET_ONE = 1;
const size_t SIZET_TWO = 2;
const size_t SIZET_THREE = 3;
const size_t SIZET_FOUR = 4;
const size_t SIZET_SIX = 6;
const size_t SIZET_SEVEN_SIX = 76;
}  // namespace
OsAccountPhotoOperator::OsAccountPhotoOperator()
{
    baseChars_ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                 "abcdefghijklmnopqrstuvwxyz"
                 "0123456789+/";
}
OsAccountPhotoOperator::~OsAccountPhotoOperator()
{}
std::string OsAccountPhotoOperator::EnCode(const char *data, size_t dataByte)
{
    std::string strEncode;
    unsigned char tmpArray[SIZET_FOUR] = {0};
    size_t LineLength = 0;
    for (size_t i = 0; i < (dataByte / SIZET_THREE); i++) {
        tmpArray[SIZET_ONE] = *data++;
        tmpArray[SIZET_TWO] = *data++;
        tmpArray[SIZET_THREE] = *data++;
        strEncode += baseChars_[tmpArray[SIZET_ONE] >> SIZET_TWO];
        strEncode += baseChars_[((tmpArray[SIZET_ONE] << SIZET_FOUR) | (tmpArray[SIZET_TWO] >> SIZET_FOUR)) & 0x3F];
        strEncode += baseChars_[((tmpArray[SIZET_TWO] << SIZET_TWO) | (tmpArray[SIZET_THREE] >> SIZET_SIX)) & 0x3F];
        strEncode += baseChars_[tmpArray[SIZET_THREE] & 0x3F];
        if (LineLength += SIZET_FOUR, LineLength == SIZET_SEVEN_SIX) {
            strEncode += "\r\n";
            LineLength = 0;
        }
    }
    size_t mod = dataByte % SIZET_THREE;
    if (mod == 1) {
        tmpArray[SIZET_ONE] = *data++;
        strEncode += baseChars_[(tmpArray[SIZET_ONE] & 0xFC) >> SIZET_TWO];
        strEncode += baseChars_[((tmpArray[SIZET_ONE] & 0x03) << SIZET_FOUR)];
        strEncode += "==";
    } else if (mod == SIZET_TWO) {
        tmpArray[SIZET_ONE] = *data++;
        tmpArray[SIZET_TWO] = *data++;
        strEncode += baseChars_[(tmpArray[SIZET_ONE] & 0xFC) >> SIZET_TWO];
        strEncode += baseChars_[((tmpArray[SIZET_ONE] & 0x03) << SIZET_FOUR) |
            ((tmpArray[SIZET_TWO] & 0xF0) >> SIZET_FOUR)];
        strEncode += baseChars_[((tmpArray[SIZET_TWO] & 0x0F) << SIZET_TWO)];
        strEncode += "=";
    }

    return strEncode;
}
std::string OsAccountPhotoOperator::DeCode(std::string const &baseStr)
{
    ACCOUNT_LOGD("OsAccountPhotoOperator DeCode Start");
    std::string byteStr;
    size_t in_len = baseStr.size();
    if (in_len == 0) {
        ACCOUNT_LOGE("empty input baseStr!");
        return byteStr;
    }

    size_t i = 0;
    size_t in_ = 0;
    unsigned char char_array_4[SIZET_FOUR];
    unsigned char char_array_3[SIZET_THREE];

    while (in_len-- && (baseStr[in_] != '=') && IsBase(baseStr[in_])) {
        char_array_4[i++] = baseStr[in_];
        in_++;
        if (i == SIZET_FOUR) {
            for (i = 0; i < SIZET_FOUR; i++)
                char_array_4[i] = baseChars_.find(char_array_4[i]);

            char_array_3[SIZET_ZERO] = (char_array_4[SIZET_ZERO] << SIZET_TWO) +
                ((char_array_4[SIZET_ONE] & 0x30) >> SIZET_FOUR);
            char_array_3[SIZET_ONE] =
                ((char_array_4[SIZET_ONE] & 0xf) << SIZET_FOUR) + ((char_array_4[SIZET_TWO] & 0x3c) >> SIZET_TWO);
            char_array_3[SIZET_TWO] = ((char_array_4[SIZET_TWO] & 0x3) << SIZET_SIX) + char_array_4[SIZET_THREE];

            for (i = 0; (i < SIZET_THREE); i++)
                byteStr += char_array_3[i];
            i = 0;
        }
    }

    if (i) {
        size_t j = 0;
        for (j = i; j < SIZET_FOUR; j++)
            char_array_4[j] = 0;

        for (j = 0; j < SIZET_FOUR; j++)
            char_array_4[j] = baseChars_.find(char_array_4[j]);

        char_array_3[SIZET_ZERO] = (char_array_4[SIZET_ZERO] << SIZET_TWO) +
            ((char_array_4[SIZET_ONE] & 0x30) >> SIZET_FOUR);
        char_array_3[SIZET_ONE] =
            ((char_array_4[SIZET_ONE] & 0xf) << SIZET_FOUR) + ((char_array_4[SIZET_TWO] & 0x3c) >> SIZET_TWO);
        char_array_3[SIZET_TWO] = ((char_array_4[SIZET_TWO] & 0x3) << SIZET_SIX) + char_array_4[SIZET_THREE];

        for (j = 0; (j < i - 1); j++)
            byteStr += char_array_3[j];
    }
    return byteStr;
}
bool OsAccountPhotoOperator::IsBase(unsigned char c)
{
    return (isalnum(c) || (c == '+') || (c == '/'));
}
}  // namespace AccountSA
}  // namespace OHOS