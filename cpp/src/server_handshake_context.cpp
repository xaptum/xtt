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

#include <xtt-cpp/server_handshake_context.hpp>

#include <stdexcept>

using namespace xtt;

server_handshake_context::server_handshake_context(unsigned char *in_buffer,
                                                   uint16_t in_buffer_size,
                                                   unsigned char *out_buffer,
                                                   uint16_t out_buffer_size)
{
    if (!in_buffer || !out_buffer)
        return;

    xtt_return_code_type rc;
    rc = xtt_initialize_server_handshake_context(&handshake_ctx_,
                                                 in_buffer,
                                                 in_buffer_size,
                                                 out_buffer,
                                                 out_buffer_size);
    if (XTT_RETURN_SUCCESS != rc) {
        throw std::runtime_error("Error initializing server handshake context");
    }
}

server_handshake_context::server_handshake_context(server_handshake_context&& other)
    : server_handshake_context(nullptr,
                               0,
                               nullptr,
                               0)
{
    swap(*this, other);
}

server_handshake_context& server_handshake_context::operator=(server_handshake_context other)
{
    swap(*this, other);

    return *this;
}

std::experimental::optional<version> server_handshake_context::get_version() const
{
    xtt_version current_version;
    if (XTT_RETURN_SUCCESS != xtt_get_version(&current_version, &handshake_ctx_)) {
        return {};
    }

    return static_cast<version>(current_version);
}

std::experimental::optional<suite_spec> server_handshake_context::get_suite_spec() const
{
    xtt_suite_spec current_suite_spec;
    if (XTT_RETURN_SUCCESS != xtt_get_suite_spec(&current_suite_spec, &handshake_ctx_)) {
        return {};
    }

    return static_cast<suite_spec>(current_suite_spec);
}

std::unique_ptr<pseudonym> server_handshake_context::get_clients_pseudonym() const
{
    switch (*get_suite_spec()) {
        case suite_spec::X25519_LRSW_ED25519_CHACHA20POLY1305_SHA512:
        case suite_spec::X25519_LRSW_ED25519_CHACHA20POLY1305_BLAKE2B:
        case suite_spec::X25519_LRSW_ED25519_AES256GCM_SHA512:
        case suite_spec::X25519_LRSW_ED25519_AES256GCM_BLAKE2B:
            {
                // Avoid double-copying
                xtt_daa_pseudonym_lrsw clients_pseudonym;
                if (XTT_RETURN_SUCCESS != xtt_get_clients_pseudonym_lrsw(&clients_pseudonym, &handshake_ctx_)) {
                    return {};
                }

                std::vector<unsigned char> clients_pseudonym_as_vec(clients_pseudonym.data, clients_pseudonym.data+sizeof(xtt_daa_pseudonym_lrsw));
                return std::make_unique<pseudonym_lrsw>(clients_pseudonym_as_vec);
            }
        default:
            return {};
    }
}

std::unique_ptr<longterm_key> server_handshake_context::get_clients_longterm_key() const
{
    switch (*get_suite_spec()) {
        case suite_spec::X25519_LRSW_ED25519_CHACHA20POLY1305_SHA512:
        case suite_spec::X25519_LRSW_ED25519_CHACHA20POLY1305_BLAKE2B:
        case suite_spec::X25519_LRSW_ED25519_AES256GCM_SHA512:
        case suite_spec::X25519_LRSW_ED25519_AES256GCM_BLAKE2B:
            {
                // Avoid double-copying
                xtt_ed25519_pub_key clients_longterm_key;
                if (XTT_RETURN_SUCCESS != xtt_get_clients_longterm_key_ed25519(&clients_longterm_key, &handshake_ctx_)) {
                    return {};
                }

                std::vector<unsigned char> clients_longterm_key_as_vec(clients_longterm_key.data, clients_longterm_key.data+sizeof(xtt_ed25519_pub_key));
                return std::make_unique<longterm_key_ed25519>(clients_longterm_key_as_vec);
            }
        default:
            return {};
    }
}

std::experimental::optional<identity> server_handshake_context::get_clients_identity() const
{
    xtt_identity_type assigned_identity;
    if (XTT_RETURN_SUCCESS != xtt_get_clients_identity(&assigned_identity, &handshake_ctx_)) {
        return {};
    }

    return identity(std::vector<unsigned char>(assigned_identity.data, assigned_identity.data + sizeof(xtt_identity_type)));
}

const struct xtt_server_handshake_context* server_handshake_context::get() const
{
    return &handshake_ctx_;
}

struct xtt_server_handshake_context* server_handshake_context::get()
{
    return &handshake_ctx_;
}

return_code server_handshake_context::handle_io(uint16_t bytes_written,
                                                uint16_t bytes_read,
                                                uint16_t& io_bytes_requested,
                                                unsigned char*& io_ptr)
{
    xtt_return_code_type ret = xtt_handshake_server_handle_io(bytes_written,
                                                              bytes_read,
                                                              &io_bytes_requested,
                                                              &io_ptr,
                                                              &handshake_ctx_);

    return static_cast<return_code>(ret);
}

return_code server_handshake_context::handle_connect(uint16_t& io_bytes_requested,
                                                     unsigned char*& io_ptr)
{
    xtt_return_code_type ret = xtt_handshake_server_handle_connect(&io_bytes_requested,
                                                                   &io_ptr,
                                                                   &handshake_ctx_);
    return static_cast<return_code>(ret);
}

return_code server_handshake_context::build_serverattest(uint16_t& io_bytes_requested,
                                                         unsigned char*& io_ptr,
                                                         const server_certificate_context& certificate_ctx,
                                                         server_cookie_context& cookie_ctx)
{
    xtt_return_code_type ret = xtt_handshake_server_build_serverattest(&io_bytes_requested,
                                                                       &io_ptr,
                                                                       &handshake_ctx_,
                                                                       certificate_ctx.get(),
                                                                       cookie_ctx.get());
    return static_cast<return_code>(ret);
}

return_code server_handshake_context::preparse_idclientattest(uint16_t& io_bytes_requested,
                                                              unsigned char*& io_ptr,
                                                              identity& requested_client_id_out,
                                                              group_identity& claimed_group_id_out,
                                                              server_cookie_context& cookie_ctx,
                                                              const server_certificate_context& certificate_ctx)
{
    xtt_return_code_type ret = xtt_handshake_server_preparse_idclientattest(&io_bytes_requested,
                                                                            &io_ptr,
                                                                            requested_client_id_out.get(),
                                                                            claimed_group_id_out.get(),
                                                                            cookie_ctx.get(),
                                                                            certificate_ctx.get(),
                                                                            &handshake_ctx_);
    return static_cast<return_code>(ret);
}

return_code server_handshake_context::verify_groupsignature(uint16_t& io_bytes_requested,
                                                            unsigned char*& io_ptr,
                                                            group_public_key_context& group_pub_key_ctx,
                                                            const server_certificate_context& certificate_ctx)
{
xtt_return_code_type ret = xtt_handshake_server_verify_groupsignature(&io_bytes_requested,
                                                                      &io_ptr,
                                                                      group_pub_key_ctx.get(),
                                                                      certificate_ctx.get(),
                                                                      &handshake_ctx_);
    return static_cast<return_code>(ret);
}

return_code server_handshake_context::build_idserverfinished(uint16_t& io_bytes_requested,
                                                             unsigned char*& io_ptr,
                                                             const identity& client_id)
{
    xtt_return_code_type ret = xtt_handshake_server_build_idserverfinished(&io_bytes_requested,
                                                                           &io_ptr,
                                                                           client_id.get(),
                                                                           &handshake_ctx_);
    return static_cast<return_code>(ret);
}

return_code server_handshake_context::build_error_msg(uint16_t& io_bytes_requested,
                                                      unsigned char*& io_ptr)
{
    return static_cast<return_code>(xtt_server_build_error_msg(&io_bytes_requested, &io_ptr, &handshake_ctx_));
}

void swap(server_handshake_context& first, server_handshake_context& second)
{
    using std::swap;

    swap(first.handshake_ctx_, second.handshake_ctx_);

    // Internal buffer pointers must be explicitly reset
    first.handshake_ctx_.base.hash_out_buffer = (unsigned char*)&first.handshake_ctx_.base.hash_out_buffer_raw;
    first.handshake_ctx_.base.inner_hash = (unsigned char*)&first.handshake_ctx_.base.inner_hash_raw;

    first.handshake_ctx_.base.shared_secret_buffer = (unsigned char*)&first.handshake_ctx_.base.shared_secret_raw;
    first.handshake_ctx_.base.handshake_secret = (unsigned char*)&first.handshake_ctx_.base.handshake_secret_raw;
    first.handshake_ctx_.base.prf_key = (unsigned char*)&first.handshake_ctx_.base.prf_key_raw;

    second.handshake_ctx_.base.hash_out_buffer = (unsigned char*)&second.handshake_ctx_.base.hash_out_buffer_raw;
    second.handshake_ctx_.base.inner_hash = (unsigned char*)&second.handshake_ctx_.base.inner_hash_raw;

    second.handshake_ctx_.base.shared_secret_buffer = (unsigned char*)&second.handshake_ctx_.base.shared_secret_raw;
    second.handshake_ctx_.base.handshake_secret = (unsigned char*)&second.handshake_ctx_.base.handshake_secret_raw;
    second.handshake_ctx_.base.prf_key = (unsigned char*)&second.handshake_ctx_.base.prf_key_raw;
}

