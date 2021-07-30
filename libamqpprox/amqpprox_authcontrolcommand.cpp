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
#include <amqpprox_authcontrolcommand.h>

#include <amqpprox_authintercept.h>
#include <amqpprox_defaultauthintercept.h>
#include <amqpprox_server.h>

#include <memory>
#include <sstream>
#include <string>

#include <boost/algorithm/string.hpp>

namespace Bloomberg {
namespace amqpprox {

AuthControlCommand::AuthControlCommand(
    std::shared_ptr<AuthInterceptInterface> &authIntercept)
: d_authIntercept_p(authIntercept)
{
}

std::string AuthControlCommand::commandVerb() const
{
    return "AUTH";
}

std::string AuthControlCommand::helpText() const
{
    return "SET hostname port target | OFF | "
           "PRINT";
}

void AuthControlCommand::handleCommand(const std::string & /* command */,
                                       const std::string &  restOfCommand,
                                       const OutputFunctor &outputFunctor,
                                       Server *             serverHandle,
                                       Control * /* controlHandle */)
{
    ControlCommandOutput<OutputFunctor> output(outputFunctor);

    std::istringstream iss(restOfCommand);
    std::string        subcommand;
    if (iss >> subcommand) {
        boost::to_upper(subcommand);

        if (subcommand == "SET") {
            std::string hostname;
            int         port = -1;
            std::string target;
            if (!(iss >> hostname)) {
                output << "No hostname specified.\n";
                return;
            }
            if (!(iss >> port && port > 0 && port <= 65535)) {
                output << "Invalid port provided.\n";
                return;
            }
            if (!(iss >> target)) {
                output << "No http target specified.\n";
                return;
            }

            d_authIntercept_p =
                std::make_shared<AuthIntercept>(serverHandle->ioService(),
                                                hostname,
                                                std::to_string(port),
                                                target,
                                                httpVersion);
        }
        else if (subcommand == "OFF") {
            d_authIntercept_p = std::make_shared<DefaultAuthIntercept>(
                serverHandle->ioService());
        }
        else if (subcommand == "PRINT") {
            std::ostringstream oss;
            d_authIntercept_p->print(output);
        }
        else {
            output << "Unknown subcommand.\n";
        }
    }
    else {
        output << "No subcommand provided.\n";
    }
}

}
}
