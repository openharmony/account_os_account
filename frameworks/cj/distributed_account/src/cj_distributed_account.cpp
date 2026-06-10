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

#include "cj_distributed_account.h"
#include "ohos_account_kits.h"

namespace OHOS {
namespace AccountSA {
char *MallocCString(const std::string &origin)
{
    if (origin.empty()) {
        return nullptr;
    }
    auto len = origin.length() + 1;
    char *res = static_cast<char *>(malloc(sizeof(char) * len));
    if (res == nullptr) {
        return nullptr;
    }
    return std::char_traits<char>::copy(res, origin.c_str(), len);
}

CJDistributedInfo convertToCJInfo(AccountSA::OhosAccountInfo ohosInfo)
{
    CJDistributedInfo cjInfo{0};
    cjInfo.name = MallocCString(ohosInfo.name_);
    cjInfo.id = MallocCString(ohosInfo.uid_);
    cjInfo.nickname = MallocCString(ohosInfo.nickname_);
    cjInfo.avatar = MallocCString(ohosInfo.avatar_);
    cjInfo.status = ohosInfo.status_;
    cjInfo.scalableData = MallocCString(ohosInfo.scalableData_);
    return cjInfo;
}

ErrCode getOhosInfoFromCJInfo(CJDistributedInfo cjInfo, AccountSA::OhosAccountInfo &ohosInfo)
{
    ErrCode errCode = OhosAccountKits::GetInstance().GetOhosAccountInfo(ohosInfo);
    if (errCode != ERR_OK) {
        return errCode;
    }
    if (cjInfo.name != nullptr) {
        ohosInfo.name_ = cjInfo.name;
    }
    if (cjInfo.id != nullptr) {
        ohosInfo.uid_ = cjInfo.id;
    }
    if (cjInfo.nickname != nullptr) {
        ohosInfo.nickname_ = cjInfo.nickname;
    }
    if (cjInfo.avatar != nullptr) {
        ohosInfo.avatar_ = cjInfo.avatar;
    }
    ohosInfo.status_ = cjInfo.status;
    if (cjInfo.scalableData != nullptr) {
        std::string scalableStr = std ::string(cjInfo.scalableData);
        ohosInfo.scalableData_ = scalableStr;
    }
    return ERR_OK;
}

extern "C"
{
    CJDistributedInfo FfiOHOSDistributedAccountDistributedInfoGetOsAccountDistributedInfo(int32_t *errCode)
    {
        AccountSA::OhosAccountInfo ohosAccountInfo;
        if (errCode == nullptr) {
            return convertToCJInfo(ohosAccountInfo);
        }
        *errCode = ConvertToJSErrCode(OhosAccountKits::GetInstance().GetOhosAccountInfo(ohosAccountInfo));
        return convertToCJInfo(ohosAccountInfo);
    }

    void FfiOHOSDistributedAccountUnitSetOsAccountDistributedInfo(CJDistributedInfo cjInfo, int32_t *errCode)
    {
        if (errCode == nullptr) {
            return;
        }
        AccountSA::OhosAccountInfo ohosAccountInfo;
        ErrCode result = getOhosInfoFromCJInfo(cjInfo, ohosAccountInfo);
        if (result != ERR_OK) {
            *errCode = ConvertToJSErrCode(result);
            return;
        }
        *errCode = ConvertToJSErrCode(
            OhosAccountKits::GetInstance().SetOhosAccountInfo(ohosAccountInfo, cjInfo.event));
    }
}
}  // namespace AccountSA
}  // namespace OHOS