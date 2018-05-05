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

#include <xtt-asio.hpp>

#include <boost/asio.hpp>

#include <cstdlib>

#include <iostream>
#include <fstream>
#include <memory>
#include <sstream>
#include <random>
#include <algorithm>

const char *daa_gpk_file = "daa_gpk.bin";
const char *basename_file = "basename.bin";
const char *server_certificate_file = "server_certificate.bin";
const char *server_privatekey_file = "server_privatekey.bin";

class xtt_server {
public:
    xtt_server(boost::asio::io_context& io_context,
               short port,
               xtt::asio::server_certificate_map& cert_map,
               xtt::server_cookie_context& cookie_ctx,
               std::unordered_map<xtt::group_identity, std::unique_ptr<xtt::group_public_key_context>>& gpk_map)
        : acceptor_(io_context, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port)),
          cert_map_(cert_map),
          cookie_ctx_(cookie_ctx),
          gpk_map_(gpk_map),
          xtt_contexts_(),
          rand_dev_(),
          unsafe_rng_(rand_dev_()),
          id_generator_(0, 255)
    {
        do_accept();
    }

private:
    void do_accept()
    {
        acceptor_.async_accept([this](boost::system::error_code ec, boost::asio::ip::tcp::socket socket)
                               {
                                   if (!ec) {
                                       run_handshake(std::move(socket));
                                   }

                                   do_accept();
                               });
    }

    void run_handshake(boost::asio::ip::tcp::socket socket)
    {
        xtt_contexts_.emplace_back(std::move(socket), cert_map_, cookie_ctx_);

        xtt_contexts_.back().async_handle_connect([this](auto&& claimed_gid,
                                                         auto&& requested_client_id,
                                                         auto&& continuation)
                                                  {
                                                      (void)requested_client_id;

                                                      auto gpk_it = gpk_map_.find(claimed_gid);
                                                      if (gpk_map_.end() == gpk_it) {
                                                          std::cerr << "Claimed group ID doesn't match any known\n";
                                                          continuation({});
                                                          return;
                                                      }

                                                      continuation(gpk_it->second->clone());
                                                  },
                                                  [this](auto&& clients_pseudonym,
                                                         auto&& clients_longterm_key,
                                                         auto&& claimed_gid,
                                                         auto&& requested_client_id,
                                                         auto&& continuation)
                                                  {
                                                      (void)clients_longterm_key;

                                                      xtt::identity assigned_id;
                                                      if (0 != assign_client_id(&assigned_id, requested_client_id, claimed_gid, std::move(clients_pseudonym))) {
                                                          std::cerr << "Unable to assign id\n";
                                                          continuation({});
                                                          return;
                                                      }

                                                      continuation(assigned_id);
                                                  },
                                                  [this](auto&& /*socket*/,
                                                         auto&& assigned_id,
                                                         auto&& clients_longterm_key,
                                                         auto&& clients_pseudonym)
                                                  {
                                                      (void)clients_longterm_key;

                                                      std::cout << "Successfully finished handshake:\n";
                                                      std::cout << "\tClient's pseudonym:       {" << clients_pseudonym->serialize_to_text() << "}\n";
                                                      std::cout << "\tWe assigned the identity: {" << assigned_id.serialize_to_text() << "}\n";
                                                      std::cout << "\tClient has longterm key:  {" << clients_longterm_key->serialize_to_text() << "}\n";
                                                  },
                                                  [this](auto&& ec)
                                                  {
                                                      std::cout << "Received error: " << ec << std::endl;
                                                  });
    }

    int
    assign_client_id(xtt::identity* assigned_client_id_out,
                     const xtt::identity& requested_client_id,
                     const xtt::group_identity& gid,
                     std::unique_ptr<xtt::pseudonym> clients_pseudonym)
    {
        // In principle, we could use the gid and pseudonym when selecting an id for the client
        // (i.e., use the gid to choose the pool of id's,
        // and use the pseudonym to ensure the same client always gets the same id).
        (void)gid;
        (void)clients_pseudonym;
    
        // If the client sent xtt_null_client_id assign them a randomly-generated id.
        // Otherwise, just echo back what they requested.
        if (requested_client_id.is_null()) {
            std::vector<unsigned char> new_id_serialized;
            std::generate_n(std::back_inserter(new_id_serialized), sizeof(xtt_identity_type), [this](){return id_generator_(unsafe_rng_);});
            *assigned_client_id_out = xtt::identity(new_id_serialized);
        } else {
            *assigned_client_id_out = requested_client_id;
        }
    
        return 0;
    }

private:
    boost::asio::ip::tcp::acceptor acceptor_;

    xtt::asio::server_certificate_map& cert_map_;
    xtt::server_cookie_context& cookie_ctx_;
    std::unordered_map<xtt::group_identity, std::unique_ptr<xtt::group_public_key_context>>& gpk_map_;

    std::vector<xtt::asio::context> xtt_contexts_;

    std::random_device rand_dev_;
    std::mt19937 unsafe_rng_;
    std::uniform_int_distribution<> id_generator_;
};

void parse_cmd_args(int argc, char *argv[], short *port);

int initialize(xtt::asio::server_certificate_map& cert_map,
               std::unordered_map<xtt::group_identity, std::unique_ptr<xtt::group_public_key_context>>& gpk_map);

int main(int argc, char *argv[])
{
    // 1) Parse args
    short server_port;
    parse_cmd_args(argc, argv, &server_port);

    // 2) Setup necessary XTT information (used by all handshakes)
    xtt::asio::server_certificate_map cert_map;
    xtt::server_cookie_context cookie_ctx;
    std::unordered_map<xtt::group_identity, std::unique_ptr<xtt::group_public_key_context>> gpk_map;
    int ret;
    ret = initialize(cert_map, gpk_map);
    if (0 != ret) {
        std::cerr << "Error initializing persistent XTT contexts\n";
        return 1;
    }

    // 3) Start server
    boost::asio::io_context io_context;
    xtt_server serv{io_context, server_port, cert_map, cookie_ctx, gpk_map};

    // 4) Run event loop
    io_context.run();
}

void parse_cmd_args(int argc, char *argv[], short *port)
{
    if (2 != argc) {
        std::cerr<< "usage: " << argv[0] << " <server port>\n";
        exit(1);
    }

    *port = std::atoi(argv[1]);
}

int initialize(xtt::asio::server_certificate_map& cert_map,
               std::unordered_map<xtt::group_identity, std::unique_ptr<xtt::group_public_key_context>>& gpk_map)
{
    // 1) Read DAA GPK from file.
    std::ifstream gpk_file(daa_gpk_file, std::ios::in | std::ios::binary);
    std::vector<unsigned char> serialized_gpk((std::istreambuf_iterator<char>(gpk_file)), std::istreambuf_iterator<char>());
    
    // 2) Read DAA basename from file
    std::ifstream bsn_file(basename_file, std::ios::in | std::ios::binary);
    std::vector<unsigned char> basename((std::istreambuf_iterator<char>(bsn_file)), std::istreambuf_iterator<char>());

    // 3) Initialize DAA context
    auto gpk = std::make_unique<xtt::group_public_key_context_lrsw>(basename, serialized_gpk);

    // 4) Generate GID from GPK (GID = SHA-256(GPK))
    xtt::group_identity gid = gpk->gid_from_sha256();

    // 4ii) Insert gpk into map
    gpk_map[gid] = std::move(gpk);

    // 5) Read in my certificate from file
    std::ifstream cert_file(server_certificate_file, std::ios::in | std::ios::binary);
    std::vector<unsigned char> serialized_cert((std::istreambuf_iterator<char>(cert_file)), std::istreambuf_iterator<char>());

    // 6) Read in my private key from file
    std::ifstream privkey_file(server_privatekey_file, std::ios::in | std::ios::binary);
    std::vector<unsigned char> serialized_privkey((std::istreambuf_iterator<char>(privkey_file)), std::istreambuf_iterator<char>());

    // 7) Initialize my certificate context
    // Currently, only Ed25519 is supported for server signatures,
    // but in the future others may be used, too.
    cert_map[xtt::suite_spec::X25519_LRSW_ED25519_CHACHA20POLY1305_SHA512] =
        std::make_unique<xtt::server_certificate_context_ed25519>(serialized_cert, serialized_privkey);
    cert_map[xtt::suite_spec::X25519_LRSW_ED25519_CHACHA20POLY1305_BLAKE2B] = 
        std::make_unique<xtt::server_certificate_context_ed25519>(serialized_cert, serialized_privkey);
    cert_map[xtt::suite_spec::X25519_LRSW_ED25519_AES256GCM_SHA512] = 
        std::make_unique<xtt::server_certificate_context_ed25519>(serialized_cert, serialized_privkey);
    cert_map[xtt::suite_spec::X25519_LRSW_ED25519_AES256GCM_BLAKE2B] = 
        std::make_unique<xtt::server_certificate_context_ed25519>(serialized_cert, serialized_privkey);

    return 0;
}
