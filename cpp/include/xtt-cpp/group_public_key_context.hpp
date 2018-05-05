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

#ifndef XTT_CPP_GROUPPUBLICKEYCONTEXT_HPP
#define XTT_CPP_GROUPPUBLICKEYCONTEXT_HPP
#pragma once

#include <xtt/context.h>

#include <xtt-cpp/group_identity.hpp>

#include <vector>
#include <memory>

namespace xtt {

class group_public_key_context {
public:
    virtual ~group_public_key_context() = default;

    virtual group_identity gid_from_sha256() const = 0;

    virtual std::unique_ptr<group_public_key_context> clone() const = 0;

    virtual std::pair<std::vector<unsigned char>, std::vector<unsigned char>> serialize() const = 0;

    virtual std::pair<std::string, std::string> serialize_to_text() const = 0;

    virtual struct xtt_group_public_key_context* get() = 0;
    virtual const struct xtt_group_public_key_context* get() const = 0;
};

class group_public_key_context_lrsw : public group_public_key_context {
public:
    group_public_key_context_lrsw();

    group_public_key_context_lrsw(const std::vector<unsigned char>& basename,
                                  const std::vector<unsigned char>& serialized_lrsw_gpk);

    group_public_key_context_lrsw(const std::string& as_text_basename,
                                  const std::string& serialized_as_text_lrsw_gpk);

    std::pair<std::vector<unsigned char>, std::vector<unsigned char>> serialize() const;

    std::pair<std::string, std::string> serialize_to_text() const;

    group_identity gid_from_sha256() const final;

    std::unique_ptr<group_public_key_context> clone() const final;

    struct xtt_group_public_key_context* get() final;
    const struct xtt_group_public_key_context* get() const final;

private:
    xtt_group_public_key_context gpk_ctx_;
};

}   // namespace xtt

#endif

