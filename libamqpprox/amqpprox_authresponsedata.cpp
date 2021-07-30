/*
** Copyright 2021 Bloomberg Finance L.P.
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#include <amqpprox_authresponsedata.h>

#include <string_view>

#include <authresponse.pb.h>
#include <sasl.pb.h>

namespace Bloomberg {
namespace amqpprox {

AuthResponseData::AuthResponseData(const AuthResult &authResult,
                                   std::string_view  reason,
                                   std::string_view  authMechanism,
                                   std::string_view  credentials)
: d_authResult(authResult)
, d_reason(reason)
, d_authMechanism(authMechanism)
, d_credentials(credentials)
{
}

bool AuthResponseData::deserializeAuthResponseData(const std::string &data)
{
    authproto::AuthResponse authResponse;
    if (!authResponse.ParseFromString(data)) {
        return false;
    }

    if (authResponse.result() == authproto::AuthResponse::ALLOW)
        d_authResult = AuthResult::ALLOW;
    else
        d_authResult = AuthResult::DENY;
    d_reason = authResponse.reason();
    if (authResponse.has_authdata()) {
        authproto::SASL sasl = authResponse.authdata();
        d_authMechanism      = sasl.authmechanism();
        d_credentials        = sasl.credentials();
    }
    return true;
}

std::ostream &operator<<(std::ostream &          os,
                         const AuthResponseData &authResponseData)
{
    os << "AuthRequestData = [Auth Result:"
       << ((authResponseData.getAuthResult() ==
            AuthResponseData::AuthResult::ALLOW)
               ? "ALLOW"
               : "DENY")
       << ", Reason: " << authResponseData.getReason()
       << ", auth mechanism:" << authResponseData.getAuthMechanism()
       << ", credentials:" << authResponseData.getCredentials() << "]";
    return os;
}

}
}
