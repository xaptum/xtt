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

namespace xtt {
namespace asio {

template<typename Handler>
void
server_handshake::async_negotiate(Handler handler)
{
    boost::asio::spawn(strand_,
                       [this, handler](boost::asio::yield_context yield)
                       {
                           group_identity claimed_group_id;
                           identity requested_client_id;

                           return_code rc = asio_runner_.do_connect_to_verifygroupsignature(yield,
                                                                                            claimed_group_id,
                                                                                            requested_client_id);

                           handler(rc,
                                   claimed_group_id,
                                   requested_client_id,
                                   this);
                       });
}

template<typename Handler>
void
server_handshake::async_verify(group_public_key_context& gpk_ctx,
                               Handler handler)
{
    const auto gpk_ctx_p = &gpk_ctx;  // to ensure we're using the reference in the lambda

    boost::asio::spawn(strand_,
                       [this, gpk_ctx_p, handler](boost::asio::yield_context yield)
                       {
                           return_code rc = asio_runner_.do_verifygroupsignature_to_buildfinished(yield,
                                                                                                  *gpk_ctx_p);

                           handler(rc,
                                   handshake_ctx_.get_clients_pseudonym(),
                                   handshake_ctx_.get_clients_longterm_key(),
                                   this);
                       });
}

template<typename Handler>
void
server_handshake::async_finish(const identity& assigned_client_id,
                               Handler handler)
{
    const auto assigned_client_id_p = &assigned_client_id;  // to ensure we're using the reference in the lambda

    boost::asio::spawn(strand_,
                       [this, assigned_client_id_p, handler](boost::asio::yield_context yield)
                       {
                           return_code rc = asio_runner_.do_buildfinished_to_finished(yield,
                                                                                      *assigned_client_id_p);

                           handler(rc,
                                   *handshake_ctx_.get_clients_identity(),
                                   handshake_ctx_.get_clients_longterm_key(),
                                   handshake_ctx_.get_clients_pseudonym(),
                                   std::move(socket_));
                       });
}

template<typename Handler>
void
server_handshake::async_send_error_and_close(Handler handler)
{
    boost::asio::spawn(strand_,
                       [this, handler](boost::asio::yield_context yield)
                       {
                           asio_runner_.send_error_msg(yield);

                           handler(return_code::SUCCESS);
                       });
}

}   // namespace asio
}   // namespace xtt

