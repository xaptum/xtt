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

#ifndef XTT_CPP_INTERNAL_TEXTTOBINARY_HPP
#define XTT_CPP_INTERNAL_TEXTTOBINARY_HPP
#pragma once

#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <experimental/optional>

inline
std::experimental::optional<unsigned char> ascii_to_byte(const char value);

inline
std::string binary_to_text(const unsigned char *binary, uint16_t size) {
    std::ostringstream ss;
    ss << std::hex << std::setfill('0') << std::uppercase;
    for (std::size_t i=0; i < size; ++i) {
        ss << std::setw(2) << static_cast<int>(binary[i]);
    }

    return ss.str();
}

inline
std::vector<unsigned char> text_to_binary(const std::string& text)
{
    if (0 != text.length() % 2) {
        return {};
    }
    std::size_t size = text.size() / 2;

    std::vector<unsigned char> ret(size);
    for (std::size_t i=0; i < size; ++i) {
        auto maybe_upper = ascii_to_byte(text[2*i]);
        auto maybe_lower = ascii_to_byte(text[2*i+1]);
        if (!maybe_upper || !maybe_lower) {
            return {};
        }

        ret[i] = *maybe_upper*16 + *maybe_lower;
    }

    return ret;
}

std::experimental::optional<unsigned char> ascii_to_byte(const char value)
{
    if (value < 0)
        return {};

    if (value >= '0' && value <= '9') {
        return std::experimental::optional<unsigned char>(static_cast<unsigned char>(value - '0'));
    }
    if (value >= 'A' && value <= 'F') {
        return std::experimental::optional<unsigned char>(static_cast<unsigned char>(value - 'A' + 10));
    }
    if (value >= 'a' && value <= 'f') {
        return std::experimental::optional<unsigned char>(static_cast<unsigned char>(value - 'a' + 10));
    }

    return {};
}

#endif

