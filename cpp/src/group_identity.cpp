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

#include <xtt-cpp/group_identity.hpp>

#include "internal/text_to_binary.hpp"

#include <xtt/crypto_wrapper.h>

#include <stdexcept>

using namespace xtt;

group_identity::group_identity(const std::vector<unsigned char>& serialized)
{
    if (sizeof(xtt_group_id) != serialized.size()) {
        throw std::runtime_error("Bad serialized value passed to group identity constructor");
    }

    raw_ = *reinterpret_cast<const xtt_group_id*>(serialized.data());
}

group_identity::group_identity(const std::string& serialized_as_text)
    : group_identity(text_to_binary(serialized_as_text))
{
}

const xtt_group_id* group_identity::get() const
{
    return &raw_;
}

xtt_group_id* group_identity::get()
{
    return &raw_;
}

std::vector<unsigned char> group_identity::serialize() const
{
    return std::vector<unsigned char>(raw_.data, raw_.data+sizeof(xtt_group_id));
}

std::string group_identity::serialize_to_text() const
{
    return binary_to_text(raw_.data, sizeof(xtt_group_id));
}

bool group_identity::operator==(const group_identity& other) const
{
    return 0 == xtt_crypto_memcmp(raw_.data,
                                  other.raw_.data,
                                  sizeof(xtt_group_id));
}

bool group_identity::operator!=(const group_identity& other) const
{
    return !(*this == other);
}

std::size_t std::hash<xtt::group_identity>::operator()(const xtt::group_identity& key) const
{
    return hash<std::string>()(std::string(reinterpret_cast<const char*>(key.get()->data), sizeof(xtt_group_id)));
}