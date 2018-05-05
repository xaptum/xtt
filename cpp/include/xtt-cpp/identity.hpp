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

#ifndef XTT_CPP_IDENTITY_HPP
#define XTT_CPP_IDENTITY_HPP
#pragma once

#include <xtt/crypto_types.h>

#include <string>
#include <vector>

namespace xtt { class identity; }
namespace std {
template<>
struct hash<xtt::identity>
{
    std::size_t operator()(const xtt::identity& key) const;
};
}

namespace xtt {

class identity {
public:
    static const identity null;

public:
    identity() = default;

    identity(const std::vector<unsigned char>& serialized);

    identity(const std::string& serialized_as_text);

    std::vector<unsigned char> serialize() const;

    std::string serialize_to_text() const;

    bool is_null() const;

    bool operator==(const identity& other) const;

    bool operator!=(const identity& other) const;

    const xtt_identity_type* get() const;
    xtt_identity_type* get();

private:
    xtt_identity_type raw_;
};

}   // namespace xtt


#endif

