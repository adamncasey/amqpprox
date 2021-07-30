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
#ifndef BLOOMBERG_AMQPPROX_AUTHINTERCEPT
#define BLOOMBERG_AMQPPROX_AUTHINTERCEPT

#include <amqpprox_authinterceptinterface.h>
#include <amqpprox_authrequestdata.h>

#include <iostream>
#include <mutex>
#include <string>

#include <boost/asio.hpp>
#include <boost/beast.hpp>

namespace Bloomberg {
namespace amqpprox {

namespace {
namespace beast = boost::beast;
using tcp       = boost::asio::ip::tcp;
}

class AuthIntercept : public AuthInterceptInterface,
                      public std::enable_shared_from_this<AuthIntercept> {
    std::string        d_hostname;
    std::string        d_port;
    std::string        d_target;
    tcp::resolver      d_resolver;
    beast::tcp_stream  d_stream;
    beast::flat_buffer d_buffer;  // (Must persist between reads)
    beast::http::request<beast::http::string_body>  d_request;
    beast::http::response<beast::http::string_body> d_response;
    mutable std::mutex                              d_mutex;

    void onResolve(const ReceiveResponseCb &   responseCb,
                   beast::error_code           ec,
                   tcp::resolver::results_type results);
    void onConnect(const ReceiveResponseCb &responseCb,
                   beast::error_code        ec,
                   tcp::resolver::results_type::endpoint_type);
    void onWrite(const ReceiveResponseCb &responseCb,
                 beast::error_code        ec,
                 std::size_t              bytes_transferred);
    void onRead(const ReceiveResponseCb &responseCb,
                beast::error_code        ec,
                std::size_t              bytes_transferred);

  public:
    // CREATORS
    AuthIntercept(boost::asio::io_service &ioService,
                  const std::string &      hostname,
                  const std::string &      port,
                  const std::string &      target);

    virtual ~AuthIntercept() override = default;

    // MANIPULATORS
    /**
     * \brief It gets all the information required to authenticate from client
     * in requestBody parameter and invoke callback function to provide
     * response.
     * \param requestBody request data payload
     * \param responseCb Callbak function with response values
     */
    virtual void sendRequest(const AuthRequestData    authRequestData,
                             const ReceiveResponseCb &responseCb) override;

    // ACCESSORS
    /**
     * \brief Print information about route auth gate service
     * \param os output stream object
     */
    virtual void print(std::ostream &os) const override;
};

}
}

#endif
