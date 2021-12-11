/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "account_log_wrapper.h"

#include "os_account_photo_operator.h"
namespace OHOS {
namespace AccountSA {
namespace {
const int INT_ZERO = 0;
const int INT_ONE = 1;
const int INT_TWO = 2;
const int INT_THREE = 3;
const int INT_FOUR = 4;
const int INT_SIX = 6;
const int INT_SEVEN_SIX = 76;
}  // namespace
OsAccountPhotoOperator::OsAccountPhotoOperator()
{
    baseChars_ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                 "abcdefghijklmnopqrstuvwxyz"
                 "0123456789+/";
}
OsAccountPhotoOperator::~OsAccountPhotoOperator()
{}
std::string OsAccountPhotoOperator::EnCode(const char *data, int dataByte)
{
    std::string strEncode;
    unsigned char tmpArray[INT_FOUR] = {0};
    int LineLength = 0;
    for (int i = 0; i < (int)(dataByte / INT_THREE); i++) {
        tmpArray[INT_ONE] = *data++;
        tmpArray[INT_TWO] = *data++;
        tmpArray[INT_THREE] = *data++;
        strEncode += baseChars_[tmpArray[INT_ONE] >> INT_TWO];
        strEncode += baseChars_[((tmpArray[INT_ONE] << INT_FOUR) | (tmpArray[INT_TWO] >> INT_FOUR)) & 0x3F];
        strEncode += baseChars_[((tmpArray[INT_TWO] << INT_TWO) | (tmpArray[INT_THREE] >> INT_SIX)) & 0x3F];
        strEncode += baseChars_[tmpArray[INT_THREE] & 0x3F];
        if (LineLength += INT_FOUR, LineLength == INT_SEVEN_SIX) {
            strEncode += "\r\n";
            LineLength = 0;
        }
    }
    int mod = dataByte % INT_THREE;
    if (mod == 1) {
        tmpArray[INT_ONE] = *data++;
        strEncode += baseChars_[(tmpArray[INT_ONE] & 0xFC) >> INT_TWO];
        strEncode += baseChars_[((tmpArray[INT_ONE] & 0x03) << INT_FOUR)];
        strEncode += "==";
    } else if (mod == INT_TWO) {
        tmpArray[INT_ONE] = *data++;
        tmpArray[INT_TWO] = *data++;
        strEncode += baseChars_[(tmpArray[INT_ONE] & 0xFC) >> INT_TWO];
        strEncode += baseChars_[((tmpArray[INT_ONE] & 0x03) << INT_FOUR) | ((tmpArray[INT_TWO] & 0xF0) >> INT_FOUR)];
        strEncode += baseChars_[((tmpArray[INT_TWO] & 0x0F) << INT_TWO)];
        strEncode += "=";
    }

    return strEncode;
}
std::string OsAccountPhotoOperator::DeCode(std::string const &baseStr)
{
    ACCOUNT_LOGE("OsAccountPhotoOperator DeCode Start");
    std::string byteStr;
    int in_len = baseStr.size();
    int i = 0;
    int j = 0;
    int in_ = 0;
    unsigned char char_array_4[INT_FOUR], char_array_3[INT_THREE];

    while (in_len-- && (baseStr[in_] != '=') && IsBase(baseStr[in_])) {
        char_array_4[i++] = baseStr[in_];
        in_++;
        if (i == INT_FOUR) {
            for (i = 0; i < INT_FOUR; i++)
                char_array_4[i] = baseChars_.find(char_array_4[i]);

            char_array_3[INT_ZERO] = (char_array_4[INT_ZERO] << INT_TWO) + ((char_array_4[INT_ONE] & 0x30) >> INT_FOUR);
            char_array_3[INT_ONE] =
                ((char_array_4[INT_ONE] & 0xf) << INT_FOUR) + ((char_array_4[INT_TWO] & 0x3c) >> INT_TWO);
            char_array_3[INT_TWO] = ((char_array_4[INT_TWO] & 0x3) << INT_SIX) + char_array_4[INT_THREE];

            for (i = 0; (i < INT_THREE); i++)
                byteStr += char_array_3[i];
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < INT_FOUR; j++)
            char_array_4[j] = 0;

        for (j = 0; j < INT_FOUR; j++)
            char_array_4[j] = baseChars_.find(char_array_4[j]);

        char_array_3[INT_ZERO] = (char_array_4[INT_ZERO] << INT_TWO) + ((char_array_4[INT_ONE] & 0x30) >> INT_FOUR);
        char_array_3[INT_ONE] =
            ((char_array_4[INT_ONE] & 0xf) << INT_FOUR) + ((char_array_4[INT_TWO] & 0x3c) >> INT_TWO);
        char_array_3[INT_TWO] = ((char_array_4[INT_TWO] & 0x3) << INT_SIX) + char_array_4[INT_THREE];

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