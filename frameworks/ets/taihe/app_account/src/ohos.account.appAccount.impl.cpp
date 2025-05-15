#include "ohos.account.appAccount.proj.hpp"
#include "ohos.account.appAccount.impl.hpp"
#include "account_error_no.h"
#include "app_account_common.h"
#include "app_account_manager.h"
#include "taihe/runtime.hpp"
#include "taihe_common.h"

#include "taihe/runtime.hpp"
#include "stdexcept"

using namespace taihe;
using namespace OHOS;
using namespace ohos::account::appAccount;

namespace {

class AppAccountManagerImpl {
public:
    AppAccountManagerImpl() {}

    void CreateAccountSync(string_view name) {
        AccountSA::CreateAccountOptions options{};
        std::string innerName(name.data(), name.size());
        int errorCode = AccountSA::AppAccountManager::CreateAccount(innerName, options);
        if (errorCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
    }

    void CreateAccountWithOpt(string_view name, CreateAccountOptions const& options) {
        std::string innerName(name.data(), name.size());
        AccountSA::CreateAccountOptions optionsInner;
        if (options.customData.has_value()) {
            for (const auto& item : options.customData.value()) {
                optionsInner.customData.emplace({item.first, item.second});
            }
        }
        int errorCode = AccountSA::AppAccountManager::CreateAccount(innerName, optionsInner);
        if (errorCode != ERR_OK) {
            int32_t jsErrCode = GenerateBusinessErrorCode(errorCode);
            taihe::set_business_error(jsErrCode, ConvertToJsErrMsg(jsErrCode));
        }
    }
};

AppAccountManager createAppAccountManager() {
    return make_holder<AppAccountManagerImpl, AppAccountManager>();
}
}  // namespace

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_createAppAccountManager(createAppAccountManager);
// NOLINTEND
