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

#ifndef XTT_ASIO_ASIORUNNER_HPP
#define XTT_ASIO_ASIORUNNER_HPP
#pragma once

#include <xtt-cpp.hpp>

#include <boost/asio/spawn.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <unordered_map>

namespace xtt {
namespace asio {

class asio_runner {
public:
    asio_runner(boost::asio::ip::tcp::socket& tcp_socket,
                server_handshake_context& handshake_ctx,
                const std::unordered_map<suite_spec, std::unique_ptr<server_certificate_context>>& cert_map,
                server_cookie_context& cookie_ctx);

    return_code
    do_connect_to_verifygroupsignature(boost::asio::yield_context yield,
                                       group_identity& claimed_group_id,
                                       identity& requested_client_id);

    return_code
    do_verifygroupsignature_to_buildfinished(boost::asio::yield_context yield,
                                             group_public_key_context& gpk_ctx);

    return_code
    do_buildfinished_to_finished(boost::asio::yield_context yield,
                                 const identity& assigned_client_id);

    void send_error_msg(boost::asio::yield_context yield);

private:
    return_code
    do_write(boost::asio::yield_context yield,
             uint16_t& bytes_requested,
             unsigned char*& io_ptr);

    return_code
    do_read(boost::asio::yield_context yield,
            uint16_t& bytes_requested,
            unsigned char*& io_ptr);

private:
    boost::asio::ip::tcp::socket& tcp_socket_;
    server_handshake_context& handshake_ctx_;
    const std::unordered_map<suite_spec, std::unique_ptr<server_certificate_context>>& cert_map_;
    server_cookie_context& cookie_ctx_;
};

}   // namespace asio
}   // namespace xtt

#endif

