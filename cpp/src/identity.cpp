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

#include <xtt-cpp/identity.hpp>

#include "internal/text_to_binary.hpp"

#include <xtt/crypto_wrapper.h>

using namespace xtt;

const identity identity::null(std::vector<unsigned char>(xtt_null_identity.data, xtt_null_identity.data + sizeof(xtt_identity_type)));

identity::identity(const std::vector<unsigned char>& serialized)
{
    if (sizeof(xtt_identity_type) != serialized.size()) {
        throw std::runtime_error("Bad serialized value passed to identity constructor");
    }

    raw_ = *reinterpret_cast<const xtt_identity_type*>(serialized.data());
}

identity::identity(const std::string& serialized_as_text)
    : identity(text_to_binary(serialized_as_text))
{
}

std::vector<unsigned char> identity::serialize() const
{
    return std::vector<unsigned char>(raw_.data, raw_.data+sizeof(xtt_identity_type));
}

std::string identity::serialize_to_text() const
{
    return binary_to_text(raw_.data, sizeof(xtt_identity_type));
}

bool identity::is_null() const
{
    return *this == identity::null;
}

const xtt_identity_type* identity::get() const
{
    return &raw_;
}

xtt_identity_type* identity::get()
{
    return &raw_;
}

bool identity::operator==(const identity& other) const
{
    return 0 == xtt_crypto_memcmp(raw_.data,
                                  other.raw_.data,
                                  sizeof(xtt_identity_type));
}

bool identity::operator!=(const identity& other) const
{
    return !(*this == other);
}

std::size_t std::hash<xtt::identity>::operator()(const xtt::identity& key) const
{
    return hash<std::string>()(std::string(reinterpret_cast<const char*>(key.get()->data), sizeof(xtt_identity_type)));
}
