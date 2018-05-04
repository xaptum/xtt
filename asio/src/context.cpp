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

#include <xtt-asio/context.hpp>

using namespace xtt;
using namespace asio;

context::context(boost::asio::ip::tcp::socket tcp_socket,
                 const server_certificate_map& cert_map,
                 server_cookie_context& cookie_ctx)
    : in_buffer_(),
      out_buffer_(),
      handshake_ctx_(in_buffer_.data(), in_buffer_.size(), out_buffer_.data(), out_buffer_.size()),
      socket_(std::move(tcp_socket)),
      cert_map_(cert_map),
      cookie_ctx_(cookie_ctx)
{
}

const boost::asio::ip::tcp::socket& 
context::lowest_layer() const
{
    return socket_;
}

boost::asio::ip::tcp::socket& 
context::lowest_layer()
{
    return socket_;
}

