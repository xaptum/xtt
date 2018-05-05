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

#include <xtt-cpp/server_certificate_context.hpp>

#include "internal/text_to_binary.hpp"

#include <stdexcept>

using namespace xtt;

const unsigned char server_certificate_ed25519_dummy[XTT_SERVER_CERTIFICATE_ED25519_LENGTH] = {0};
const xtt_ed25519_priv_key server_privatekey_ed25519_dummy = {{0}};

server_certificate_context_ed25519::server_certificate_context_ed25519()
{
    xtt_return_code_type ctor_ret =
        xtt_initialize_server_certificate_context_ed25519(&certificate_ctx_,
                                                          server_certificate_ed25519_dummy,
                                                          &server_privatekey_ed25519_dummy);
    if (XTT_RETURN_SUCCESS != ctor_ret) {
        throw std::runtime_error("Error encountered in Ed25519 server certificate constructor");
    }
}

server_certificate_context_ed25519::server_certificate_context_ed25519(const server_certificate_context_ed25519& other)
    : certificate_ctx_(other.certificate_ctx_)
{
    // Internal buffer pointers must be explicitly reset
    certificate_ctx_.serialized_certificate = (struct xtt_server_certificate_raw_type*)certificate_ctx_.serialized_certificate_raw;
}

server_certificate_context_ed25519::server_certificate_context_ed25519(server_certificate_context_ed25519&& other)
    : server_certificate_context_ed25519()
{
    swap(*this, other);
}

server_certificate_context_ed25519& server_certificate_context_ed25519::operator=(server_certificate_context_ed25519 other)
{
    swap(*this, other);

    return *this;
}

struct xtt_server_certificate_context* server_certificate_context_ed25519::get()
{
    return &certificate_ctx_;
}

const struct xtt_server_certificate_context* server_certificate_context_ed25519::get() const
{
    return &certificate_ctx_;
}

void swap(server_certificate_context_ed25519& first, server_certificate_context_ed25519& second)
{
    using std::swap;

    swap(first.certificate_ctx_, second.certificate_ctx_);

    // Internal buffer pointers must be explicitly reset
    first.certificate_ctx_.serialized_certificate = (struct xtt_server_certificate_raw_type*)first.certificate_ctx_.serialized_certificate_raw;
    second.certificate_ctx_.serialized_certificate = (struct xtt_server_certificate_raw_type*)second.certificate_ctx_.serialized_certificate_raw;
}

server_certificate_context_ed25519::server_certificate_context_ed25519(const std::vector<unsigned char>& serialized_certificate,
                                                                       const std::vector<unsigned char>& serialized_private_key)
{
    if (XTT_SERVER_CERTIFICATE_ED25519_LENGTH != serialized_certificate.size() ||
        sizeof(xtt_ed25519_priv_key) != serialized_private_key.size()) {
        throw std::runtime_error("Bad serialized value passed to Ed25519 server certificate constructor");
    }

    xtt_return_code_type ctor_ret =
        xtt_initialize_server_certificate_context_ed25519(&certificate_ctx_,
                                                          serialized_certificate.data(),
                                                          reinterpret_cast<const xtt_ed25519_priv_key*>(serialized_private_key.data()));
    if (XTT_RETURN_SUCCESS != ctor_ret) {
        throw std::runtime_error("Error encountered in Ed25519 server certificate constructor");
    }
}

server_certificate_context_ed25519::server_certificate_context_ed25519(const std::string& serialized_as_text_certificate,
                                                                       const std::string& serialized_as_text_private_key)
    : server_certificate_context_ed25519(text_to_binary(serialized_as_text_certificate),
                                         text_to_binary(serialized_as_text_private_key))
{
}

std::unique_ptr<server_certificate_context> server_certificate_context_ed25519::clone() const
{
    return std::make_unique<server_certificate_context_ed25519>(*this);
}

std::pair<std::vector<unsigned char>, std::vector<unsigned char>> server_certificate_context_ed25519::serialize() const
{
    return std::make_pair(std::vector<unsigned char>(certificate_ctx_.serialized_certificate_raw,
                                                     certificate_ctx_.serialized_certificate_raw+XTT_SERVER_CERTIFICATE_ED25519_LENGTH),
                          std::vector<unsigned char>(certificate_ctx_.private_key.ed25519.data,
                                                     certificate_ctx_.private_key.ed25519.data+sizeof(xtt_ed25519_priv_key)));
}

std::pair<std::string, std::string> server_certificate_context_ed25519::serialize_to_text() const
{
    return std::make_pair(binary_to_text(certificate_ctx_.serialized_certificate_raw, XTT_SERVER_CERTIFICATE_ED25519_LENGTH),
                          binary_to_text(certificate_ctx_.private_key.ed25519.data, sizeof(xtt_ed25519_priv_key)));
}
