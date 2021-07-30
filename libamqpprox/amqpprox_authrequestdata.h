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
#ifndef BLOOMBERG_AMQPPROX_AUTHREQUESTDATA
#define BLOOMBERG_AMQPPROX_AUTHREQUESTDATA

#include <iostream>
#include <string>
#include <string_view>

namespace Bloomberg {
namespace amqpprox {

/**
 * \brief Provide a class to hold request data for authn/authz operations
 */
class AuthRequestData {
    std::string d_vhostName;
    std::string d_authMechanism;
    std::string d_credentials;

  public:
    /**
     * \brief Create and initialize object of AuthRequestData class
     * \param vhostName vhost name
     * \param authMechanism authentication mechanism field for START-OK
     * connection method
     * \param credentials response field for START-OK connection method
     */
    AuthRequestData(std::string_view vhostName,
                    std::string_view authMechanism,
                    std::string_view credentials);

    AuthRequestData();

    /**
     * \return vhost name
     */
    inline const std::string getVhostName() const;

    /**
     * \return authentication mechanism field for START-OK connection method.
     * This field will be extracted from START-OK connection method sent from
     * the client.
     */
    inline const std::string getAuthMechanism() const;

    /**
     * \return response field for START-OK connection method. This field will
     * be extracted from START-OK connection method sent from the client.
     */
    inline const std::string getCredentials() const;

    /**
     * \brief Serialize auth request data using protobuf. Schema is defined in
     * authrequest.proto file.
     * \param ouput Pointer to serialized byte data in std::string format
     * \return true in case of successful serialization, otherwise false
     */
    bool serializeAuthRequestData(std::string *output) const;
};

inline const std::string AuthRequestData::getVhostName() const
{
    return d_vhostName;
}

inline const std::string AuthRequestData::getAuthMechanism() const
{
    return d_authMechanism;
}

inline const std::string AuthRequestData::getCredentials() const
{
    return d_credentials;
}

std::ostream &operator<<(std::ostream &         os,
                         const AuthRequestData &authRequestData);

}
}

#endif
