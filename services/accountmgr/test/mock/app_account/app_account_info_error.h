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

#ifndef OS_ACCOUNT_SERVICES_ACCOUNTMGR_TEST_MOCK_APP_ACCOUNT_INFO_ERROR_H
#define OS_ACCOUNT_SERVICES_ACCOUNTMGR_TEST_MOCK_APP_ACCOUNT_INFO_ERROR_H

namespace OHOS {
namespace AccountSA {
enum AccountDataStorageErrType {
    ERR_ACCOUNTDATASTORAGE_FAILED = -1,
    ERR_ACCOUNTDATASTORAGE_OK = 0,
    ERR_ACCOUNTDATASTORAGE_STARTDB,
    ERR_ACCOUNTDATASTORAGE_PUTVALUEKVSTORE,
    ERR_ACCOUNTDATASTORAGE_COMMITDB,
    ERR_ACCOUNTDATASTORAGE_SAVEINFO,
    ERR_ACCOUNTDATASTORAGE_GETVALUEKVSTORE,
    ERR_ACCOUNTDATASTORAGE_LOADDATA,
};

extern int g_accountDataStorageErrType;
}
}
#endif // OS_ACCOUNT_SERVICES_ACCOUNTMGR_TEST_MOCK_APP_ACCOUNT_INFO_ERROR_H