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

#include <amqpprox_authintercept.h>

#include <amqpprox_authinterceptinterface.h>
#include <amqpprox_authrequestdata.h>
#include <amqpprox_authresponsedata.h>
#include <amqpprox_logging.h>

#include <functional>
#include <iomanip>
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

int   timeoutSeconds = 30;
float httpVersion    = 1.1;
}

AuthIntercept::AuthIntercept(boost::asio::io_service &ioService,
                             const std::string &      hostname,
                             const std::string &      port,
                             const std::string &      target)
: AuthInterceptInterface(ioService)
, d_hostname(hostname)
, d_port(port)
, d_target(target)
, d_resolver(boost::asio::make_strand(ioService))
, d_stream(boost::asio::make_strand(ioService))
{
}

void AuthIntercept::sendRequest(const AuthRequestData    authRequestData,
                                const ReceiveResponseCb &responseCb)
{
    d_request.version(static_cast<int>(httpVersion * 10));  // HTTP/1.1 version
    d_request.method(beast::http::verb::post);
    d_request.target(d_target);
    d_request.set(beast::http::field::host, d_hostname);
    d_request.set(beast::http::field::user_agent, BOOST_BEAST_VERSION_STRING);
    d_request.set(beast::http::field::content_type,
                  "application/json; charset=utf-8");
    std::string serializedRequestBody;
    if (!authRequestData.serializeAuthRequestData(&serializedRequestBody)) {
        const std::string errorMsg =
            "Unable to serialize auth request data for http service.";
        LOG_ERROR << errorMsg;
        responseCb(
            AuthResponseData(AuthResponseData::AuthResult::DENY, errorMsg));
        return;
    }
    d_request.body() = serializedRequestBody;
    d_request.prepare_payload();

    // Look up the domain name
    d_resolver.async_resolve(
        d_hostname,
        d_port,
        beast::bind_front_handler(
            &AuthIntercept::onResolve, shared_from_this(), responseCb));
}

void AuthIntercept::onResolve(const ReceiveResponseCb &   responseCb,
                              beast::error_code           ec,
                              tcp::resolver::results_type results)
{
    if (ec) {
        const std::string errorMsg =
            "Unable to resolve hostname " + d_hostname +
            ", ReturnCode: " + std::to_string(ec.value());
        LOG_ERROR << errorMsg;
        responseCb(
            AuthResponseData(AuthResponseData::AuthResult::DENY, errorMsg));
        return;
    }

    // Set a timeout on the operation
    d_stream.expires_after(std::chrono::seconds(timeoutSeconds));

    // Make the connection on the IP address we get from a lookup
    d_stream.async_connect(results,
                           beast::bind_front_handler(&AuthIntercept::onConnect,
                                                     shared_from_this(),
                                                     responseCb));
}

void AuthIntercept::onConnect(const ReceiveResponseCb &responseCb,
                              beast::error_code        ec,
                              tcp::resolver::results_type::endpoint_type)
{
    if (ec) {
        const std::string errorMsg =
            "Unable to connect hostname " + d_hostname + " on port " + d_port +
            ", ReturnCode: " + std::to_string(ec.value());
        LOG_ERROR << errorMsg;
        responseCb(
            AuthResponseData(AuthResponseData::AuthResult::DENY, errorMsg));
        return;
    }

    // Set a timeout on the operation
    d_stream.expires_after(std::chrono::seconds(timeoutSeconds));

    // Send the HTTP request to the remote host
    beast::http::async_write(d_stream,
                             d_request,
                             beast::bind_front_handler(&AuthIntercept::onWrite,
                                                       shared_from_this(),
                                                       responseCb));
}

void AuthIntercept::onWrite(const ReceiveResponseCb &responseCb,
                            beast::error_code        ec,
                            std::size_t              bytes_transferred)
{
    boost::ignore_unused(bytes_transferred);

    if (ec) {
        const std::string errorMsg =
            "Unable to send http request to hostname " + d_hostname +
            " on port " + d_port +
            ", ReturnCode: " + std::to_string(ec.value());
        LOG_ERROR << errorMsg;
        responseCb(
            AuthResponseData(AuthResponseData::AuthResult::DENY, errorMsg));
        return;
    }

    // Receive the HTTP response
    beast::http::async_read(d_stream,
                            d_buffer,
                            d_response,
                            beast::bind_front_handler(&AuthIntercept::onRead,
                                                      shared_from_this(),
                                                      responseCb));
}

void AuthIntercept::onRead(const ReceiveResponseCb &responseCb,
                           beast::error_code        ec,
                           std::size_t              bytes_transferred)
{
    boost::ignore_unused(bytes_transferred);

    if (ec) {
        const std::string errorMsg =
            "Unable to receive http response from hostname " + d_hostname +
            " on port " + d_port +
            ", ReturnCode: " + std::to_string(ec.value());
        LOG_ERROR << errorMsg;
        responseCb(
            AuthResponseData(AuthResponseData::AuthResult::DENY, errorMsg));
        return;
    }

    // Write the message to standard out
    LOG_TRACE << "Response from auth route gate service at " << d_hostname
              << ":" << d_port << d_target << ": " << d_response;

    AuthResponseData authResponseData;
    if (!authResponseData.deserializeAuthResponseData(d_response.body())) {
        const std::string errorMsg = "Unable to deserialize auth response "
                                     "data received from http service.";
        LOG_ERROR << errorMsg;
        responseCb(
            AuthResponseData(AuthResponseData::AuthResult::DENY, errorMsg));
        return;
    }
    responseCb(authResponseData);

    // Gracefully close the socket
    d_stream.socket().shutdown(tcp::socket::shutdown_both, ec);

    // not_connected happens sometimes so don't bother reporting it.
    if (ec && ec != beast::errc::not_connected) {
        const std::string errorMsg =
            "Unable to close socket and shutdown connection gracefully for "
            "auth route gate service at " +
            d_hostname + ":" + d_port + d_target +
            ", ReturnCode: " + std::to_string(ec.value());
        LOG_WARN << errorMsg;
        return;
    }

    // If we get here then the connection is closed gracefully
}

void AuthIntercept::print(std::ostream &os) const
{
    std::lock_guard<std::mutex> lg(d_mutex);
    os << "Auth service will be used to authn/authz client connections.\n"
       << "Hostname: " << d_hostname << "\n"
       << "Port: " << d_port << "\n"
       << "Target: " << d_target << "\n"
       << "HTTP version: " << std::fixed << std::setprecision(1) << httpVersion
       << "\n";
}
}
}
