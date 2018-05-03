/******************************************************************************
 *
 * Copyright 2018 Xaptum, Inc.
 * 
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 * 
 *        http://www.apache.org/licenses/LICENSE-2.0
 * 
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License
 *
 *****************************************************************************/

#ifndef XTT_ASIO_SERVERHANDSHAKE_HPP
#define XTT_ASIO_SERVERHANDSHAKE_HPP
#pragma once

#include <xtt-cpp.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/io_service.hpp>

#include <xtt-asio/asio_runner.hpp>

#include <memory>
#include <unordered_map>

namespace xtt {
namespace asio {

class server_handshake {
public:
    server_handshake(boost::asio::ip::tcp::socket tcp_socket,
                     const std::unordered_map<suite_spec, std::unique_ptr<server_certificate_context>>& cert_map,
                     server_cookie_context& cookie_ctx);

    const boost::asio::ip::tcp::socket& lowest_layer() const;
    boost::asio::ip::tcp::socket& lowest_layer();
                 
    template<typename Handler>
    void
    async_negotiate(Handler handler);
                 
    template<typename Handler>
    void
    async_verify(xtt::group_public_key_context& gpk_ctx,
                 Handler handler);

    template<typename Handler>
    void
    async_finish(const identity& assigned_client_id,
                 Handler handler);

    template<typename Handler>
    void
    async_send_error_and_close(Handler handler);

private:
    std::array<unsigned char, MAX_HANDSHAKE_CLIENT_MESSAGE_LENGTH> in_buffer_;
    std::array<unsigned char, MAX_HANDSHAKE_SERVER_MESSAGE_LENGTH> out_buffer_;
    server_handshake_context handshake_ctx_;
    boost::asio::ip::tcp::socket socket_;
    boost::asio::io_service::strand strand_;
    asio_runner asio_runner_;
};

}   // namespace asio
}   // namespace xtt

#include "server_handshake.inl"

#endif

