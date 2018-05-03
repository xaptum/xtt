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

#include <xtt-asio/asio_runner.hpp>

#include <boost/asio/write.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/system/error_code.hpp>

using namespace xtt;
using namespace asio;

asio_runner::asio_runner(boost::asio::ip::tcp::socket& tcp_socket,
                         server_handshake_context& handshake_ctx,
                         const std::unordered_map<suite_spec, std::unique_ptr<server_certificate_context>>& cert_map,
                         server_cookie_context& cookie_ctx)
    : tcp_socket_(tcp_socket),
      handshake_ctx_(handshake_ctx),
      cert_map_(cert_map),
      cookie_ctx_(cookie_ctx)
{
}

return_code
asio_runner::do_write(boost::asio::yield_context yield,
                               uint16_t& bytes_requested,
                               unsigned char*& io_ptr)
{
    boost::system::error_code ec;
    std::size_t write_length = tcp_socket_.async_write_some(boost::asio::buffer(io_ptr,
                                                                                bytes_requested),
                                                            yield[ec]);
    if (ec) {
        return return_code::BAD_IO;
    }

    return handshake_ctx_.handle_io(write_length,
                                    0,  // no bytes read
                                    bytes_requested,
                                    io_ptr);
}

return_code
asio_runner::do_read(boost::asio::yield_context yield,
                              uint16_t& bytes_requested,
                              unsigned char*& io_ptr)
{
    boost::system::error_code ec;
    std::size_t read_length = tcp_socket_.async_read_some(boost::asio::buffer(io_ptr,
                                                                              bytes_requested),
                                                          yield[ec]);
    if (ec) {
        return return_code::BAD_IO;
    }

    return handshake_ctx_.handle_io(0,  // no bytes written
                                    read_length,
                                    bytes_requested,
                                    io_ptr);
}

void
asio_runner::send_error_msg(boost::asio::yield_context yield)
{
    uint16_t bytes_requested = 0;
    unsigned char *io_ptr = NULL;
    (void)handshake_ctx_.build_error_msg(bytes_requested, io_ptr);
    (void)tcp_socket_.async_write_some(boost::asio::buffer(io_ptr,
                                                           bytes_requested),
                                       yield);
}

return_code
asio_runner::do_connect_to_verifygroupsignature(boost::asio::yield_context yield,
                                                     group_identity& claimed_group_id,
                                                     identity& requested_client_id)
{
    uint16_t bytes_requested = 0;
    unsigned char *io_ptr = NULL;

    return_code current_status = handshake_ctx_.handle_connect(bytes_requested,
                                                               io_ptr);

    while (return_code::WANT_VERIFYGROUPSIGNATURE != current_status) {
        switch (current_status) {
            case return_code::WANT_WRITE:
                {
                    current_status = do_write(yield, bytes_requested, io_ptr);

                    break;
                }
            case return_code::WANT_READ:
                {
                    current_status = do_read(yield, bytes_requested, io_ptr);

                    break;
                }
            case return_code::WANT_BUILDSERVERATTEST:
                {
                    auto suite_spec = handshake_ctx_.get_suite_spec();
                    if (!suite_spec) {
                        return return_code::UNKNOWN_SUITE_SPEC;
                    }

                    auto cert = cert_map_.find(*suite_spec);
                    if (cert_map_.end() == cert) {
                        send_error_msg(yield);
                        return return_code::BAD_CERTIFICATE;
                    }

                    current_status = handshake_ctx_.build_serverattest(bytes_requested,
                                                                       io_ptr,
                                                                       *cert->second,
                                                                       cookie_ctx_);

                    break;
                }
            case return_code::WANT_PREPARSEIDCLIENTATTEST:
                {
                    auto suite_spec = handshake_ctx_.get_suite_spec();
                    if (!suite_spec) {
                        return return_code::UNKNOWN_SUITE_SPEC;
                    }

                    auto cert = cert_map_.find(*suite_spec);
                    if (cert_map_.end() == cert) {
                        send_error_msg(yield);
                        return return_code::BAD_CERTIFICATE;
                    }

                    current_status = handshake_ctx_.preparse_idclientattest(bytes_requested,
                                                                            io_ptr,
                                                                            requested_client_id,
                                                                            claimed_group_id,
                                                                            cookie_ctx_,
                                                                            *cert->second);

                    break;
                }
            case return_code::WANT_VERIFYGROUPSIGNATURE:
                return current_status;
            case return_code::RECEIVED_ERROR_MSG:
                return current_status;
            default:
                send_error_msg(yield);
                return current_status;
        }
    }

    return current_status;
}

return_code
asio_runner::do_verifygroupsignature_to_buildfinished(boost::asio::yield_context yield,
                                                           group_public_key_context& gpk_ctx)
{
    uint16_t bytes_requested = 0;
    unsigned char *io_ptr = NULL;

    return_code current_status = return_code::WANT_VERIFYGROUPSIGNATURE;

    while (return_code::WANT_BUILDIDSERVERFINISHED != current_status) {
        switch (current_status) {
            case return_code::WANT_WRITE:
                {
                    current_status = do_write(yield, bytes_requested, io_ptr);

                    break;
                }
            case return_code::WANT_READ:
                {
                    current_status = do_read(yield, bytes_requested, io_ptr);

                    break;
                }
            case return_code::WANT_VERIFYGROUPSIGNATURE:
                {
                    auto suite_spec = handshake_ctx_.get_suite_spec();
                    if (!suite_spec) {
                        return return_code::UNKNOWN_SUITE_SPEC;
                    }

                    auto cert = cert_map_.find(*suite_spec);
                    if (cert_map_.end() == cert) {
                        send_error_msg(yield);
                        return return_code::BAD_CERTIFICATE;
                    }

                    current_status = handshake_ctx_.verify_groupsignature(bytes_requested,
                                                                          io_ptr,
                                                                          gpk_ctx,
                                                                          *cert->second);

                    break;
                }
            case return_code::WANT_BUILDIDSERVERFINISHED:
                return current_status;
            case return_code::RECEIVED_ERROR_MSG:
                return current_status;
            default:
                send_error_msg(yield);
                return current_status;
        }
    }

    return current_status;
}

return_code
asio_runner::do_buildfinished_to_finished(boost::asio::yield_context yield,
                                               const identity& assigned_client_id)
{
    uint16_t bytes_requested = 0;
    unsigned char *io_ptr = NULL;

    return_code current_status = return_code::WANT_BUILDIDSERVERFINISHED;

    while (return_code::HANDSHAKE_FINISHED != current_status) {
        switch (current_status) {
            case return_code::WANT_WRITE:
                {
                    current_status = do_write(yield, bytes_requested, io_ptr);

                    break;
                }
            case return_code::WANT_READ:
                {
                    current_status = do_read(yield, bytes_requested, io_ptr);

                    break;
                }
            case return_code::WANT_BUILDIDSERVERFINISHED:
                {
                    current_status = handshake_ctx_.build_idserverfinished(bytes_requested,
                                                                           io_ptr,
                                                                           assigned_client_id);

                    break;
                }
            case return_code::HANDSHAKE_FINISHED:
                return current_status;
            case return_code::RECEIVED_ERROR_MSG:
                return current_status;
            default:
                send_error_msg(yield);
                return current_status;
        }
    }

    return current_status;
}
