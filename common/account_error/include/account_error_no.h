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

#ifndef BASE_ACCOUNT_INCLUDE_ACCOUNT_ERROR_NO_H
#define BASE_ACCOUNT_INCLUDE_ACCOUNT_ERROR_NO_H

#include "errors.h"

namespace OHOS {
    enum {
        ACCOUNT_MODULE_COMMON = 0x00,
        ACCOUNT_MODULE_ACCOUNTMGR,
        ACCOUNT_MODULE_DATADEAL,
        ACCOUNT_MODULE_IACCOUNT
    };

    /* Error code for common */
    constexpr ErrCode ACCOUNT_COMMON_ERR_OFFSET = ErrCodeOffset(SUBSYS_ACCOUNT, ACCOUNT_MODULE_COMMON);

    /* Error code for AccountMgr */
    constexpr ErrCode ACCOUNT_ACCOUNTMGR_ERR_OFFSET = ErrCodeOffset(SUBSYS_ACCOUNT, ACCOUNT_MODULE_ACCOUNTMGR);
    enum {
        ERR_ACCOUNT_MGR_DUMP_ERROR = ACCOUNT_ACCOUNTMGR_ERR_OFFSET + 0x0001,
        ERR_ACCOUNT_MGR_GET_REMOTE_SA_ERROR,
        ERR_ACCOUNT_MGR_CONNECT_SA_ERROR,
        ERR_ACCOUNT_MGR_ADD_TO_SA_ERROR
    };

    /* Error code for DataDeal module */
    constexpr ErrCode ACCOUNT_DATADEAL_ERR_OFFSET = ErrCodeOffset(SUBSYS_ACCOUNT, ACCOUNT_MODULE_DATADEAL);
    enum {
        ERR_ACCOUNT_DATADEAL_INPUT_FILE_ERROR = ACCOUNT_DATADEAL_ERR_OFFSET + 0x0001,
        ERR_ACCOUNT_DATADEAL_FILE_PARSE_FAILED,
        ERR_ACCOUNT_DATADEAL_DIGEST_ERROR,
        ERR_ACCOUNT_DATADEAL_FILE_WRITE_FAILED,
        ERR_ACCOUNT_DATADEAL_JSON_KEY_NOT_EXIST,
        ERR_ACCOUNT_DATADEAL_NOT_READY,
        ERR_ACCOUNT_DATADEAL_JSON_FILE_CORRUPTION
    };

    /* Error code for IAccount */
    constexpr ErrCode ACCOUNT_IACCOUNT_ERR_OFFSET = ErrCodeOffset(SUBSYS_ACCOUNT, ACCOUNT_MODULE_IACCOUNT);
    enum {
        ERR_ACCOUNT_ZIDL_ACCOUNT_INFO_CHECK_ERROR = ACCOUNT_IACCOUNT_ERR_OFFSET + 0x0001,
        ERR_ACCOUNT_ZIDL_WRITE_DESCRIPTOR_ERROR,
        ERR_ACCOUNT_ZIDL_READ_RESULT_ERROR,
        ERR_ACCOUNT_ZIDL_WRITE_RESULT_ERROR,
        ERR_ACCOUNT_ZIDL_ACCOUNT_STUB_ERROR,
        ERR_ACCOUNT_ZIDL_ACCOUNT_SEND_REQUEST_ERROR,
        ERR_ACCOUNT_ZIDL_WRITE_NAME_ERROR,
        ERR_ACCOUNT_ZIDL_WRITE_UID_ERROR,
        ERR_ACCOUNT_ZIDL_WRITE_ACCOUNT_STATUS_ERROR,
        ERR_ACCOUNT_ZIDL_MGR_NOT_READY_ERROR,
        ERR_ACCOUNT_ZIDL_CHECK_PERMISSION_ERROR,
        ERR_ACCOUNT_ZIDL_WRITE_PARCEL_DATA_ERROR,
        ERR_ACCOUNT_ZIDL_INVALID_RESULT_ERROR
    };
}

#endif /* BASE_ACCOUNT_INCLUDE_ACCOUNT_ERROR_NO_H */
