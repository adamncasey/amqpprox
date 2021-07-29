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

#include <amqpprox_defaultauthintercept.h>

#include <amqpprox_authinterceptinterface.h>
#include <amqpprox_authrequestdata.h>
#include <amqpprox_authresponsedata.h>

#include <iostream>

#include <boost/asio.hpp>

namespace Bloomberg {
namespace amqpprox {

DefaultAuthIntercept::DefaultAuthIntercept(boost::asio::io_service &ioService)
: AuthInterceptInterface(ioService)
{
}

void DefaultAuthIntercept::sendRequest(const AuthRequestData,
                                       const ReceiveResponseCb &responseCb)
{
    auto cb = [responseCb] {
        AuthResponseData authResponseData(AuthResponseData::AuthResult::ALLOW,
                                          "Default auth gate service");
        responseCb(authResponseData);
    };
    boost::asio::post(d_ioService, cb);
}

void DefaultAuthIntercept::print(std::ostream &os) const
{
    os << "No external auth service will be used to authn/authz client "
          "connections.\n";
}

}
}
