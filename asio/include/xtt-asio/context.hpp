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

#ifndef XTT_ASIO_CONTEXT_HPP
#define XTT_ASIO_CONTEXT_HPP
#pragma once

#include <xtt-cpp.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/io_service.hpp>

#include <memory>
#include <unordered_map>
#include <functional>

namespace xtt {
namespace asio {

    using server_certificate_map = std::unordered_map<suite_spec, std::unique_ptr<server_certificate_context>>;

    class context {
    public:
        context(boost::asio::ip::tcp::socket tcp_socket,
                const server_certificate_map& cert_map,
                server_cookie_context& cookie_ctx);

        const boost::asio::ip::tcp::socket& lowest_layer() const;
        boost::asio::ip::tcp::socket& lowest_layer();

        template <typename GPKLookupCallback,
                  typename AssignIdCallback,
                  typename SuccessCallback,
                  typename ErrorCallback>
        void async_handle_connect(GPKLookupCallback gpk_lookup_callback,
                                  AssignIdCallback assign_id_callback,
                                  SuccessCallback success_callback,
                                  ErrorCallback error_callback);

    private:
        template <typename GPKLookupCallback,
                  typename AssignIdCallback,
                  typename SuccessCallback,
                  typename ErrorCallback>
        void
        run_state_machine(return_code current_rc,
                          uint16_t bytes_requested,
                          unsigned char *io_ptr,
                          GPKLookupCallback gpk_lookup_callback,
                          AssignIdCallback assign_id_callback,
                          SuccessCallback success_callback,
                          ErrorCallback error_callback);

        template <typename Handler>
        void
        send_error_msg(Handler handler);

    private:
        std::array<unsigned char, MAX_HANDSHAKE_CLIENT_MESSAGE_LENGTH> in_buffer_;
        std::array<unsigned char, MAX_HANDSHAKE_SERVER_MESSAGE_LENGTH> out_buffer_;
        server_handshake_context handshake_ctx_;
        boost::asio::ip::tcp::socket socket_;
        xtt::identity requested_client_id_;
        xtt::group_identity claimed_group_id_;
        const server_certificate_map& cert_map_;
        server_cookie_context& cookie_ctx_;
    };

}   // namespace asio
}   // namespace xtt

#include "context.inl"

#endif

