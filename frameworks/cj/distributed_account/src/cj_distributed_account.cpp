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

RetDistributedInfo convertToRet(AccountSA::OhosAccountInfo ohosInfo)
{
    RetDistributedInfo retInfo{0};
    retInfo.name = MallocCString(ohosInfo.name_);
    retInfo.id = MallocCString(ohosInfo.uid_);
    retInfo.nickname = MallocCString(ohosInfo.nickname_);
    retInfo.avatar = MallocCString(ohosInfo.avatar_);
    retInfo.status = ohosInfo.status_;
    return retInfo;
}

AccountSA::OhosAccountInfo getOhosInfoFromRet(RetDistributedInfo retInfo)
{
    AccountSA::OhosAccountInfo ohosInfo;
    OhosAccountKits::GetInstance().GetOhosAccountInfo(ohosInfo);
    ohosInfo.name_ = retInfo.name;
    ohosInfo.uid_ = retInfo.id;
    ohosInfo.nickname_ = retInfo.nickname;
    ohosInfo.avatar_ = retInfo.avatar;
    ohosInfo.status_ = retInfo.status;
    return ohosInfo;
}

extern "C"
{
    RetDistributedInfo FfiOHOSDistributedAccountDistributedInfoGetOsAccountDistributedInfo(int32_t *errCode)
    {
        AccountSA::OhosAccountInfo ohosAccountInfo;
        if (errCode == nullptr) {
            return convertToRet(ohosAccountInfo);
        }
        *errCode = ConvertToJSErrCode(OhosAccountKits::GetInstance().GetOhosAccountInfo(ohosAccountInfo));
        return convertToRet(ohosAccountInfo);
    }

    void FfiOHOSDistributedAccountUnitSetOsAccountDistributedInfo(RetDistributedInfo retInfo, int32_t *errCode)
    {
        AccountSA::OhosAccountInfo ohosAccountInfo = getOhosInfoFromRet(retInfo);
        if (errCode == nullptr) {
            return;
        }
        *errCode = ConvertToJSErrCode(
            OhosAccountKits::GetInstance().SetOhosAccountInfo(ohosAccountInfo, retInfo.event));
    }
}
}  // namespace AccountSA
}  // namespace OHOS