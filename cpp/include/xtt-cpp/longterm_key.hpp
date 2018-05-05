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

#ifndef XTT_CPP_LONGTERMKEY_HPP
#define XTT_CPP_LONGTERMKEY_HPP
#pragma once

#include <xtt/crypto_types.h>

#include <string>
#include <vector>

namespace xtt {

class longterm_key {
public:
    virtual ~longterm_key() = default;

    virtual std::unique_ptr<longterm_key> clone() const = 0;

    virtual std::vector<unsigned char> serialize() const = 0;

    virtual std::string serialize_to_text() const = 0;

    virtual const xtt_ed25519_pub_key* get() const = 0;
    virtual xtt_ed25519_pub_key* get() = 0;
};

class longterm_key_ed25519 : public longterm_key {
public:
    longterm_key_ed25519() = default;

    std::unique_ptr<longterm_key> clone() const final;

    longterm_key_ed25519(const std::vector<unsigned char>& serialized);

    longterm_key_ed25519(const std::string& serialized_as_text);

    std::vector<unsigned char> serialize() const final;

    std::string serialize_to_text() const final;

    const xtt_ed25519_pub_key* get() const final;
    xtt_ed25519_pub_key* get() final;

private:
    xtt_ed25519_pub_key raw_;
};

class longterm_private_key {
public:
    virtual ~longterm_private_key() = default;

    virtual std::unique_ptr<longterm_private_key> clone() const = 0;

    virtual std::vector<unsigned char> serialize() const = 0;

    virtual std::string serialize_to_text() const = 0;

    virtual const xtt_ed25519_priv_key* get() const = 0;
    virtual xtt_ed25519_priv_key* get() = 0;
};

class longterm_private_key_ed25519 : public longterm_private_key {
public:
    longterm_private_key_ed25519() = default;

    std::unique_ptr<longterm_private_key> clone() const final;

    longterm_private_key_ed25519(const std::vector<unsigned char>& serialized);

    longterm_private_key_ed25519(const std::string& serialized_as_text);

    std::vector<unsigned char> serialize() const final;

    std::string serialize_to_text() const final;

    const xtt_ed25519_priv_key* get() const final;
    xtt_ed25519_priv_key* get() final;

private:
    xtt_ed25519_priv_key raw_;
};

}   // namespace xtt

#endif

