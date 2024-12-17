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

#include "getpropertybycredentialidstub_fuzzer.h"

#include <string>
#include <vector>
#include "account_iam_callback_service.h"
#include "account_iam_client.h"
#include "account_iam_service.h"
#include "account_log_wrapper.h"
#include "fuzz_data.h"
#include "iaccount_iam.h"

using namespace std;
using namespace OHOS::AccountSA;
namespace OHOS {
const std::u16string IAMACCOUNT_TOKEN = u"ohos.accountfwk.IAccountIAM";

class MockGetSetPropCallback : public OHOS::AccountSA::GetSetPropCallback {
public:
    virtual ~MockGetSetPropCallback() {}
    void OnResult(int32_t result, const Attributes &extraInfo) override
    {
        return;
    }
};

bool GetPropertyByCredentialIdStubFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return false;
    }
    FuzzData fuzzData(data, size);
    uint64_t credentialId = fuzzData.GetData<uint64_t>();
    std::vector<Attributes::AttributeKey> keys = {
        fuzzData.GenerateEnmu(Attributes::AttributeKey::ATTR_AUTH_INTENTION)
    };
    std::shared_ptr<GetSetPropCallback> ptr = make_shared<MockGetSetPropCallback>();
    sptr<IGetSetPropCallback> callback = new (std::nothrow) GetSetPropCallbackService(ptr);

    MessageParcel dataTemp;
    if (!dataTemp.WriteInterfaceToken(IAMACCOUNT_TOKEN)) {
        return false;
    }
    if (!dataTemp.WriteUint64(credentialId)) {
        return false;
    }
    std::vector<uint32_t> attrKeys;
    std::transform(keys.begin(), keys.end(), std::back_inserter(attrKeys),
        [](const auto &key) { return static_cast<uint32_t>(key); });

    if (!dataTemp.WriteUInt32Vector(attrKeys)) {
        return false;
    }
    if (!dataTemp.WriteRemoteObject(callback->AsObject())) {
        return false;
    }

    MessageParcel reply;
    MessageOption option;
    uint32_t code = static_cast<uint32_t>(AccountIAMInterfaceCode::GET_PROPERTY_BY_CREDENTIAL_ID);
    auto iamAccountManagerService = std::make_shared<AccountIAMService>();
    iamAccountManagerService->OnRemoteRequest(code, dataTemp, reply, option);

    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::GetPropertyByCredentialIdStubFuzzTest(data, size);
    return 0;
}
