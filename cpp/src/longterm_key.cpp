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

#include <xtt-cpp/longterm_key.hpp>

#include "internal/text_to_binary.hpp"

#include <ostream>

using namespace xtt;

longterm_key_ed25519::longterm_key_ed25519(const std::vector<unsigned char>& serialized)
{
    if (sizeof(xtt_ed25519_pub_key) != serialized.size()) {
        throw std::runtime_error("Bad serialized value passed to Ed25519 longterm key constructor");
    }

    raw_ = *reinterpret_cast<const xtt_ed25519_pub_key*>(serialized.data());
}

longterm_key_ed25519::longterm_key_ed25519(const std::string& serialized_as_text)
    : longterm_key_ed25519(text_to_binary(serialized_as_text))
{
}

std::unique_ptr<longterm_key> longterm_key_ed25519::clone() const
{
    return std::make_unique<longterm_key_ed25519>(*this);
}

std::vector<unsigned char> longterm_key_ed25519::serialize() const
{
    return std::vector<unsigned char>(raw_.data, raw_.data+sizeof(xtt_ed25519_pub_key));
}

std::string longterm_key_ed25519::serialize_to_text() const
{
    return binary_to_text(raw_.data, sizeof(xtt_ed25519_pub_key));
}

const xtt_ed25519_pub_key* longterm_key_ed25519::get() const
{
    return &raw_;
}

xtt_ed25519_pub_key* longterm_key_ed25519::get()
{
    return &raw_;
}

longterm_private_key_ed25519::longterm_private_key_ed25519(const std::vector<unsigned char>& serialized)
{
    if (sizeof(xtt_ed25519_priv_key) != serialized.size()) {
        throw std::runtime_error("Bad serialized value passed to Ed25519 longterm private key constructor");
    }

    raw_ = *reinterpret_cast<const xtt_ed25519_priv_key*>(serialized.data());
}

longterm_private_key_ed25519::longterm_private_key_ed25519(const std::string& serialized_as_text)
    : longterm_private_key_ed25519(text_to_binary(serialized_as_text))
{
}

std::unique_ptr<longterm_private_key> longterm_private_key_ed25519::clone() const
{
    return std::make_unique<longterm_private_key_ed25519>(*this);
}

std::vector<unsigned char> longterm_private_key_ed25519::serialize() const
{
    return std::vector<unsigned char>(raw_.data, raw_.data+sizeof(xtt_ed25519_priv_key));
}

std::string longterm_private_key_ed25519::serialize_to_text() const
{
    return binary_to_text(raw_.data, sizeof(xtt_ed25519_priv_key));
}

const xtt_ed25519_priv_key* longterm_private_key_ed25519::get() const
{
    return &raw_;
}

xtt_ed25519_priv_key* longterm_private_key_ed25519::get()
{
    return &raw_;
}

