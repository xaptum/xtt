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

    template <typename GPKLookupCallback,
              typename AssignIdCallback,
              typename SuccessCallback,
              typename ErrorCallback>
    void
    context::run_state_machine(return_code current_rc,
                               uint16_t bytes_requested,
                               unsigned char *io_ptr,
                               GPKLookupCallback gpk_lookup_callback,
                               AssignIdCallback assign_id_callback,
                               SuccessCallback success_callback,
                               ErrorCallback error_callback)
    {
        switch (current_rc) {
            case return_code::WANT_WRITE:
                {
                    socket_.async_write_some(boost::asio::buffer(io_ptr,
                                                                 bytes_requested),
                                             [this, gpk_lookup_callback, assign_id_callback, success_callback, error_callback](auto&& ec, auto&& bytes_transferred)
                                             {
                                                 if (ec) {
                                                     error_callback(ec);
                                                     return;
                                                 }

                                                 uint16_t bytes_requested = 0;
                                                 unsigned char *io_ptr = NULL;

                                                 return_code current_rc = handshake_ctx_.handle_io(bytes_transferred,
                                                                                                   0,  // no bytes read
                                                                                                   bytes_requested,
                                                                                                   io_ptr);

                                                 run_state_machine(current_rc,
                                                                   bytes_requested,
                                                                   io_ptr,
                                                                   gpk_lookup_callback,
                                                                   assign_id_callback,
                                                                   success_callback,
                                                                   error_callback);
                                             });
                    break;
                }
            case return_code::WANT_READ:
                {
                    socket_.async_read_some(boost::asio::buffer(io_ptr,
                                                                bytes_requested),
                                             [this,gpk_lookup_callback, assign_id_callback, success_callback, error_callback](auto&& ec, auto&& bytes_transferred)
                                             {
                                                 if (ec) {
                                                     error_callback(ec);
                                                     return;
                                                 }

                                                 uint16_t bytes_requested = 0;
                                                 unsigned char *io_ptr = NULL;

                                                 return_code current_rc = handshake_ctx_.handle_io(0,   // no bytes written
                                                                                                   bytes_transferred,
                                                                                                   bytes_requested,
                                                                                                   io_ptr);

                                                 run_state_machine(current_rc,
                                                                   bytes_requested,
                                                                   io_ptr,
                                                                   gpk_lookup_callback,
                                                                   assign_id_callback,
                                                                   success_callback,
                                                                   error_callback);
                                             });
                    break;
                }
            case return_code::WANT_BUILDSERVERATTEST:
                {
                    auto suite_spec = handshake_ctx_.get_suite_spec();
                    if (!suite_spec) {
                        send_error_msg([error_callback]()
                                       {
                                           error_callback(return_code::UNKNOWN_SUITE_SPEC);
                                       });
                        return;
                    }

                    auto cert = cert_map_.find(*suite_spec);
                    if (cert_map_.end() == cert) {
                        send_error_msg([error_callback]()
                                       {
                                           error_callback(return_code::BAD_CERTIFICATE);
                                       });
                        return;
                    }

                    return_code new_rc = handshake_ctx_.build_serverattest(bytes_requested,
                                                                           io_ptr,
                                                                           *cert->second,
                                                                           cookie_ctx_);

                    run_state_machine(new_rc,
                                      bytes_requested,
                                      io_ptr,
                                      gpk_lookup_callback,
                                      assign_id_callback,
                                      success_callback,
                                      error_callback);

                    break;
                }
            case return_code::WANT_PREPARSEIDCLIENTATTEST:
                {
                    auto suite_spec = handshake_ctx_.get_suite_spec();
                    if (!suite_spec) {
                        send_error_msg([error_callback]()
                                       {
                                           error_callback(return_code::UNKNOWN_SUITE_SPEC);
                                       });
                        return;
                    }

                    auto cert = cert_map_.find(*suite_spec);
                    if (cert_map_.end() == cert) {
                        send_error_msg([error_callback]()
                                       {
                                           error_callback(return_code::BAD_CERTIFICATE);
                                       });
                        return;
                    }

                    return_code new_rc = handshake_ctx_.preparse_idclientattest(bytes_requested,
                                                                                io_ptr,
                                                                                requested_client_id_,
                                                                                claimed_group_id_,
                                                                                cookie_ctx_,
                                                                                *cert->second);

                    run_state_machine(new_rc,
                                      bytes_requested,
                                      io_ptr,
                                      gpk_lookup_callback,
                                      assign_id_callback,
                                      success_callback,
                                      error_callback);

                    break;
                }
            case return_code::WANT_VERIFYGROUPSIGNATURE:
               boost::asio::post(socket_.get_executor(), 
                                 [this, gpk_lookup_callback, assign_id_callback, success_callback, error_callback]()
                                 {
                                     gpk_lookup_callback(claimed_group_id_,
                                                        requested_client_id_,
                                                        [this, gpk_lookup_callback, assign_id_callback, success_callback, error_callback]
                                                        (std::unique_ptr<group_public_key_context> gpk_ctx)
                                                        {
                                                            boost::asio::post(socket_.get_executor(), 
                                                                              [this, gpk_lookup_callback, assign_id_callback, success_callback, error_callback, gpk_ctx{std::move(gpk_ctx)}]()
                                                                              {
                                                                                  if (!gpk_ctx) {
                                                                                      send_error_msg([error_callback]()
                                                                                                     {
                                                                                                         error_callback(return_code::BAD_GPK);
                                                                                                     });
                                                                                      return;
                                                                                  }

                                                                                  auto suite_spec = handshake_ctx_.get_suite_spec();
                                                                                  if (!suite_spec) {
                                                                                      send_error_msg([error_callback]()
                                                                                                     {
                                                                                                         error_callback(return_code::UNKNOWN_SUITE_SPEC);
                                                                                                     });
                                                                                      return;
                                                                                  }

                                                                                  auto cert = cert_map_.find(*suite_spec);
                                                                                  if (cert_map_.end() == cert) {
                                                                                      send_error_msg([error_callback]()
                                                                                                     {
                                                                                                         error_callback(return_code::BAD_CERTIFICATE);
                                                                                                     });
                                                                                      return;
                                                                                  }

                                                                                  uint16_t bytes_requested = 0;
                                                                                  unsigned char *io_ptr = NULL;
                                                                                  return_code new_rc = handshake_ctx_.verify_groupsignature(bytes_requested,
                                                                                                                                            io_ptr,
                                                                                                                                            *gpk_ctx,
                                                                                                                                            *cert->second);

                                                                                  run_state_machine(new_rc,
                                                                                                    bytes_requested,
                                                                                                    io_ptr,
                                                                                                    gpk_lookup_callback,
                                                                                                    assign_id_callback,
                                                                                                    success_callback,
                                                                                                    error_callback);
                                                                              });

                                                        });
                                 });

               break;

            case return_code::WANT_BUILDIDSERVERFINISHED:
               boost::asio::post(socket_.get_executor(), 
                                 [this, gpk_lookup_callback, assign_id_callback, success_callback, error_callback]()
                                 {
                                     assign_id_callback(handshake_ctx_.get_clients_pseudonym(),
                                                        handshake_ctx_.get_clients_longterm_key(),
                                                        claimed_group_id_,
                                                        requested_client_id_,
                                                        [this, gpk_lookup_callback, assign_id_callback, success_callback, error_callback]
                                                        (std::experimental::optional<identity> assigned_id)
                                                        {
                                                            boost::asio::post(socket_.get_executor(), 
                                                                              [this, gpk_lookup_callback, assign_id_callback, success_callback, error_callback, assigned_id]()
                                                                              {
                                                                                  if (!assigned_id) {
                                                                                      send_error_msg([error_callback]()
                                                                                                     {
                                                                                                         error_callback(return_code::BAD_ID);
                                                                                                     });
                                                                                      return;
                                                                                  }

                                                                                  uint16_t bytes_requested = 0;
                                                                                  unsigned char *io_ptr = NULL;
                                                                                  return_code new_rc = handshake_ctx_.build_idserverfinished(bytes_requested,
                                                                                                                                             io_ptr,
                                                                                                                                             *assigned_id);

                                                                                  run_state_machine(new_rc,
                                                                                                    bytes_requested,
                                                                                                    io_ptr,
                                                                                                    gpk_lookup_callback,
                                                                                                    assign_id_callback,
                                                                                                    success_callback,
                                                                                                    error_callback);
                                                                              });
                                                        });
                                 });

                break;
            case return_code::HANDSHAKE_FINISHED:
               boost::asio::post(socket_.get_executor(), 
                                 [this, gpk_lookup_callback, assign_id_callback, success_callback, error_callback]()
                                 {
                                     auto assigned_id = handshake_ctx_.get_clients_identity();
                                     if (assigned_id) {
                                         success_callback(std::move(socket_),
                                                          *assigned_id,
                                                          handshake_ctx_.get_clients_longterm_key(),
                                                          handshake_ctx_.get_clients_pseudonym());
                                     } else {
                                         send_error_msg([error_callback]()
                                                        {
                                                            error_callback(return_code::BAD_ID);
                                                        });
                                     }
                                 });

                break;
            case return_code::RECEIVED_ERROR_MSG:
                error_callback(return_code::RECEIVED_ERROR_MSG);
                return;
            default:
                send_error_msg([error_callback, current_rc]()
                               {
                                   error_callback(current_rc);
                               });
                return;
        }
    }

    template <typename GPKLookupCallback,
              typename AssignIdCallback,
              typename SuccessCallback,
              typename ErrorCallback>
    void
    context::async_handle_connect(GPKLookupCallback gpk_lookup_callback,
                                  AssignIdCallback assign_id_callback,
                                  SuccessCallback success_callback,
                                  ErrorCallback error_callback)
    {
        boost::asio::post(socket_.get_executor(), 
                          [this, gpk_lookup_callback, assign_id_callback, success_callback, error_callback]()
                          {
                              uint16_t bytes_requested = 0;
                              unsigned char *io_ptr = NULL;
                              return_code current_rc = handshake_ctx_.handle_connect(bytes_requested,
                                                                                     io_ptr);

                              run_state_machine(current_rc,
                                                bytes_requested,
                                                io_ptr,
                                                gpk_lookup_callback,
                                                assign_id_callback,
                                                success_callback,
                                                error_callback);
                          });
    }

    template <typename Handler>
    void
    context::send_error_msg(Handler handler)
    {
        uint16_t bytes_requested = 0;
        unsigned char *io_ptr = NULL;
        (void)handshake_ctx_.build_error_msg(bytes_requested, io_ptr);
        socket_.async_write_some(boost::asio::buffer(io_ptr,
                                                     bytes_requested),
                                 [handler](auto&& /*ec*/, auto&& /*bytes_transferred*/)
                                 {
                                     // Don't even check ec, just always raise callback
                                     handler();
                                 });
    }

}   // namespace asio
}   // namespace xtt

