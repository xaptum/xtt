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

#ifndef XTT_CPP_SERVERCERTIFICATECONTEXT_HPP
#define XTT_CPP_SERVERCERTIFICATECONTEXT_HPP
#pragma once

#include <xtt/context.h>

#include <vector>
#include <string>
#include <utility>

namespace xtt { class server_certificate_context_ed25519; }
void swap(xtt::server_certificate_context_ed25519&, xtt::server_certificate_context_ed25519&);

namespace xtt {

class server_certificate_context {
public:
    virtual ~server_certificate_context() = default;

    virtual std::unique_ptr<server_certificate_context> clone() const = 0;

    virtual std::pair<std::vector<unsigned char>, std::vector<unsigned char>> serialize() const = 0;

    virtual std::pair<std::string, std::string> serialize_to_text() const = 0;

    virtual struct xtt_server_certificate_context* get() = 0;
    virtual const struct xtt_server_certificate_context* get() const = 0;
};

class server_certificate_context_ed25519 : public server_certificate_context {
public:
    server_certificate_context_ed25519();

    server_certificate_context_ed25519(const server_certificate_context_ed25519&);

    server_certificate_context_ed25519(server_certificate_context_ed25519&& other);

    server_certificate_context_ed25519& operator=(server_certificate_context_ed25519 other);

    server_certificate_context_ed25519(const std::vector<unsigned char>& serialized_certificate,
                                       const std::vector<unsigned char>& serialized_private_key);

    server_certificate_context_ed25519(const std::string& serialized_as_text_certificate,
                                       const std::string& serialized_as_text_private_key);

    std::unique_ptr<server_certificate_context> clone() const final;

    std::pair<std::vector<unsigned char>, std::vector<unsigned char>> serialize() const final;

    std::pair<std::string, std::string> serialize_to_text() const final;

    struct xtt_server_certificate_context* get() final;
    const struct xtt_server_certificate_context* get() const final;

    friend void ::swap(server_certificate_context_ed25519& first, server_certificate_context_ed25519& second);

private:
    xtt_server_certificate_context certificate_ctx_;
};

}   // namespace xtt

#endif

