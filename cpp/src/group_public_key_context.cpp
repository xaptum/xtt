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

#include <xtt-cpp/group_public_key_context.hpp>

#include <xtt/crypto_wrapper.h>

#include <stdexcept>
#include <vector>
#include <algorithm>

using namespace xtt;

#include "internal/text_to_binary.hpp"

const xtt_daa_group_pub_key_lrsw group_public_key_lrsw_dummy = {{0}};

group_public_key_context_lrsw::group_public_key_context_lrsw()
{
    xtt_return_code_type ctor_ret =
        xtt_initialize_group_public_key_context_lrsw(&gpk_ctx_,
                                                     nullptr,
                                                     0,
                                                     &group_public_key_lrsw_dummy);
    if (XTT_RETURN_SUCCESS != ctor_ret) {
        throw std::runtime_error("Error encountered in LRSW group public key context constructor");
    }
}

struct xtt_group_public_key_context* group_public_key_context_lrsw::get()
{
    return &gpk_ctx_;
}

const struct xtt_group_public_key_context* group_public_key_context_lrsw::get() const
{
    return &gpk_ctx_;
}

group_public_key_context_lrsw::group_public_key_context_lrsw(const std::vector<unsigned char>& basename,
                                                             const std::vector<unsigned char>& serialized_lrsw_gpk)
{
    if (MAX_BASENAME_LENGTH < basename.size()) {
        throw std::runtime_error("Bad serialized basename value passed to LRSW group public key context constructor");
    }

    if (sizeof(xtt_daa_group_pub_key_lrsw) != serialized_lrsw_gpk.size()) {
        throw std::runtime_error("Bad serialized GPK value passed to LRSW group public key context constructor");
    }

    xtt_return_code_type ctor_ret =
        xtt_initialize_group_public_key_context_lrsw(&gpk_ctx_,
                                                     basename.data(),
                                                     basename.size(),
                                                     reinterpret_cast<const xtt_daa_group_pub_key_lrsw*>(serialized_lrsw_gpk.data()));
    if (XTT_RETURN_SUCCESS != ctor_ret) {
        throw std::runtime_error("Error encountered in LRSW group public key context constructor");
    }
}

group_public_key_context_lrsw::group_public_key_context_lrsw(const std::string& as_text_basename,
                                                             const std::string& serialized_as_text_lrsw_gpk)
    : group_public_key_context_lrsw(text_to_binary(as_text_basename),
                                    text_to_binary(serialized_as_text_lrsw_gpk))
{
}

std::pair<std::vector<unsigned char>, std::vector<unsigned char>> group_public_key_context_lrsw::serialize() const
{
    return std::make_pair(std::vector<unsigned char>(gpk_ctx_.basename,
                                                     gpk_ctx_.basename+std::min<std::size_t>(gpk_ctx_.basename_length, MAX_BASENAME_LENGTH)),
                          std::vector<unsigned char>(gpk_ctx_.gpk.lrsw.data,
                                                     gpk_ctx_.gpk.lrsw.data+sizeof(xtt_daa_group_pub_key_lrsw)));
}

std::pair<std::string, std::string> group_public_key_context_lrsw::serialize_to_text() const
{
    return std::make_pair(binary_to_text(gpk_ctx_.basename, std::min<std::size_t>(gpk_ctx_.basename_length, MAX_BASENAME_LENGTH)),
                          binary_to_text(gpk_ctx_.gpk.lrsw.data, sizeof(xtt_daa_group_pub_key_lrsw)));
}

group_identity group_public_key_context_lrsw::gid_from_sha256() const
{
    uint16_t hash_len;
    std::vector<unsigned char> raw_gid(sizeof(xtt_sha256));
    int hash_ret = xtt_crypto_hash_sha256(raw_gid.data(),
                                          &hash_len,
                                          gpk_ctx_.gpk.lrsw.data,
                                          sizeof(xtt_daa_group_pub_key_lrsw));
    if (0 != hash_ret || sizeof(xtt_sha256) != hash_len)
        raw_gid.clear();    // will cause the group_identity ctor to fail below

    return group_identity(raw_gid);
}

std::unique_ptr<group_public_key_context> group_public_key_context_lrsw::clone() const
{
    return std::make_unique<group_public_key_context_lrsw>(*this);
}
