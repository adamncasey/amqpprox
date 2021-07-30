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

#include <amqpprox_authrequestdata.h>

#include <authrequest.pb.h>
#include <sasl.pb.h>

namespace Bloomberg {
namespace amqpprox {

AuthRequestData::AuthRequestData(std::string_view vhostName,
                                 std::string_view authMechanism,
                                 std::string_view credentials)
: d_vhostName(vhostName)
, d_authMechanism(authMechanism)
, d_credentials(credentials)
{
}

AuthRequestData::AuthRequestData()
: d_vhostName()
, d_authMechanism()
, d_credentials()
{
}

bool AuthRequestData::serializeAuthRequestData(std::string *output) const
{
    authproto::AuthRequest authRequest;
    authRequest.set_vhostname(d_vhostName);
    authproto::SASL *sasl = authRequest.mutable_authdata();
    sasl->set_authmechanism(d_authMechanism);
    sasl->set_credentials(d_credentials);
    return authRequest.SerializeToString(output);
}

std::ostream &operator<<(std::ostream &         os,
                         const AuthRequestData &authRequestData)
{
    os << "AuthRequestData = [vhost name:" << authRequestData.getVhostName()
       << ", auth mechanism:" << authRequestData.getAuthMechanism()
       << ", credentials:" << authRequestData.getCredentials() << "]";
    return os;
}

}
}
