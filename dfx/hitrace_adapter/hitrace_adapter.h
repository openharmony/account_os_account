/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_DFX_HITRACE_ADAPTER_H
#define OS_ACCOUNT_DFX_HITRACE_ADAPTER_H

#include <string>
namespace OHOS {
namespace AccountSA {
void StartTraceAdapter(const std::string &value);
void FinishTraceAdapter();
void CountTraceAdapter(const std::string &name, int64_t count);
void UpdateTraceLabelAdapter();
} // AccountSA
} // OHOS
#endif // OS_ACCOUNT_DFX_HITRACE_ADAPTER_H
