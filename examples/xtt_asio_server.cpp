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
#include <xtt-cpp.hpp>
#include <xtt.h>

#include <boost/asio/io_service.hpp>
#include <boost/asio/spawn.hpp>

#include <memory>
#include <experimental/optional>
#include <iostream>
#include <unordered_map>
#include <sstream>
#include <random>
#include <algorithm>
#include <vector>
#include <fstream>

const char *daa_gpk_file = "daa_gpk.bin";
const char *basename_file = "basename.bin";
const char *server_certificate_file = "server_certificate.bin";
const char *server_privatekey_file = "server_privatekey.bin";

void parse_cmd_args(int argc, char *argv[], unsigned short *port);

int initialize(std::unordered_map<xtt::suite_spec, std::unique_ptr<xtt::server_certificate_context>>& cert_map,
               std::unordered_map<xtt::group_identity, std::unique_ptr<xtt::group_public_key_context>>& gpk_map);

class id_provisioner : public std::enable_shared_from_this<id_provisioner> {
public:
    id_provisioner(boost::asio::ip::tcp::socket tcp_socket,
                   const std::unordered_map<xtt::suite_spec, std::unique_ptr<xtt::server_certificate_context>>& cert_map,
                   xtt::server_cookie_context& cookie_ctx,
                   std::unordered_map<xtt::group_identity, std::unique_ptr<xtt::group_public_key_context>>& gpk_map);

    void run();

private:
    void first_callback(xtt::return_code rc,
                        const xtt::group_identity& claimed_gid,
                        const xtt::identity& requested_client_id,
                        xtt::asio::server_handshake* closure);

    void second_callback(xtt::return_code rc,
                         std::unique_ptr<xtt::pseudonym> clients_pseudonym,
                         std::unique_ptr<xtt::longterm_key> clients_longterm_key,
                         xtt::asio::server_handshake* closure);

    void third_callback(xtt::return_code rc,
                        const xtt::identity& assigned_id,
                        std::unique_ptr<xtt::longterm_key> clients_longterm_key,
                        std::unique_ptr<xtt::pseudonym> clients_pseudonym,
                        boost::asio::ip::tcp::socket tcp_socket);

private:
    int assign_client_id(xtt::identity* assigned_client_id_out,
                         const xtt::identity& requested_client_id,
                         const xtt::group_identity& gid,
                         std::unique_ptr<xtt::pseudonym> clients_pseudonym);

private:
    xtt::asio::server_handshake handshake_;
    std::unordered_map<xtt::group_identity, std::unique_ptr<xtt::group_public_key_context>>& gpk_map_;
    xtt::group_identity claimed_gid_;
    xtt::identity requested_client_id_;
    std::random_device rand_dev_;
    std::mt19937 unsafe_rng_;
};

int main(int argc, char *argv[])
{
    // 1) Parse args
    unsigned short server_port;
    parse_cmd_args(argc, argv, &server_port);

    // 2) Setup necessary XTT information (used by all handshakes
    std::unordered_map<xtt::suite_spec, std::unique_ptr<xtt::server_certificate_context>> cert_map;
    xtt::server_cookie_context cookie_ctx;
    std::unordered_map<xtt::group_identity, std::unique_ptr<xtt::group_public_key_context>> gpk_map;
    int ret;
    ret = initialize(cert_map, gpk_map);
    if (0 != ret) {
        std::cerr << "Error initializing persistent XTT contexts\n";
        return 1;
    }

    // Set up an asynchronous server, to listen for incoming connections
    boost::asio::io_service ioservice;
    boost::asio::ip::tcp::endpoint tcp_endpoint(boost::asio::ip::tcp::v4(), server_port);
    boost::asio::ip::tcp::acceptor tcp_acceptor(ioservice, tcp_endpoint);
    tcp_acceptor.listen();

    boost::asio::spawn(ioservice,
                       [&](boost::asio::yield_context yield)
                       {
                           while (true) {
                               boost::asio::ip::tcp::socket sock{ioservice};
                               tcp_acceptor.async_accept(sock, yield);

                               std::make_shared<id_provisioner>(std::move(sock), cert_map, cookie_ctx, gpk_map)->run();
                           }
                       });

    ioservice.run();
}

void parse_cmd_args(int argc, char *argv[], unsigned short *port)
{
    if (2 != argc) {
        std::cerr<< "usage: " << argv[0] << " <server port>\n";
        exit(1);
    }

    *port = atoi(argv[1]);
}

int initialize(std::unordered_map<xtt::suite_spec, std::unique_ptr<xtt::server_certificate_context>>& cert_map,
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

id_provisioner::id_provisioner(boost::asio::ip::tcp::socket tcp_socket,
                               const std::unordered_map<xtt::suite_spec, std::unique_ptr<xtt::server_certificate_context>>& cert_map,
                               xtt::server_cookie_context& cookie_ctx,
                               std::unordered_map<xtt::group_identity, std::unique_ptr<xtt::group_public_key_context>>& gpk_map)
    : handshake_(std::move(tcp_socket), cert_map, cookie_ctx),
      gpk_map_(gpk_map),
      claimed_gid_(),
      rand_dev_(),
      unsafe_rng_(rand_dev_())
{
}

void id_provisioner::run()
{
    auto self = shared_from_this();

    handshake_.async_negotiate([this, self](auto rc,
                                            auto claimed_gid,
                                            auto requested_client_id,
                                            auto closure)
                               {
                                   first_callback(rc, claimed_gid, requested_client_id, closure);
                               });
}

int
id_provisioner::assign_client_id(xtt::identity* assigned_client_id_out,
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
        std::generate_n(std::back_inserter(new_id_serialized), sizeof(xtt_identity_type), unsafe_rng_);
        *assigned_client_id_out = xtt::identity(new_id_serialized);
    } else {
        *assigned_client_id_out = requested_client_id;
    }

    return 0;
}

void id_provisioner::first_callback(xtt::return_code rc,
                                    const xtt::group_identity& claimed_gid,
                                    const xtt::identity& requested_client_id,
                                    xtt::asio::server_handshake* closure)
{
    if (xtt::return_code::WANT_VERIFYGROUPSIGNATURE != rc) {
        std::cerr << "Error with first stage of handshake\n";
        // self now goes out of scope, releasing its memory (thus closing socket in handshake_)
        return;
    } else {
        claimed_gid_ = claimed_gid;
        requested_client_id_ = requested_client_id;
        auto gpk_it = gpk_map_.find(claimed_gid_);
        if (gpk_map_.end() == gpk_it) {
            std::cerr << "Claimed group ID doesn't match any known\n";
            auto self = shared_from_this();
            closure->async_send_error_and_close([self](auto /*rc*/) { });
            return;
        }

        auto self = shared_from_this();

        closure->async_verify(*gpk_it->second,
                              [this, self](auto rc,
                                           auto clients_pseudonym,
                                           auto clients_longterm_key,
                                           auto closure)
                              {
                                   second_callback(rc, std::move(clients_pseudonym), std::move(clients_longterm_key), closure);
                              });
    }
}

void id_provisioner::second_callback(xtt::return_code rc,
                                     std::unique_ptr<xtt::pseudonym> clients_pseudonym,
                                     std::unique_ptr<xtt::longterm_key> clients_longterm_key,
                                     xtt::asio::server_handshake* closure)
{
    (void)clients_longterm_key;

    if (xtt::return_code::WANT_BUILDIDSERVERFINISHED != rc) {
        std::cerr << "Error with second stage of handshake\n";
        // self now goes out of scope, releasing its memory (thus closing socket in handshake_)
        return;
    } else {
        xtt::identity assigned_id;
        if (0 != assign_client_id(&assigned_id, requested_client_id_, claimed_gid_, std::move(clients_pseudonym))) {
            std::cerr << "Unable to assign id\n";
            auto self = shared_from_this();
            closure->async_send_error_and_close([self](auto /*rc*/) { });
            return;
        }

        auto self = shared_from_this();

        closure->async_finish(assigned_id,
                              [this, self](auto rc,
                                     auto assigned_id,
                                     auto clients_longterm_key,
                                     auto clients_pseudonym,
                                     auto tcp_socket)
                              {
                                  third_callback(rc,
                                                 assigned_id,
                                                 std::move(clients_longterm_key),
                                                 std::move(clients_pseudonym),
                                                 std::move(tcp_socket));
                              });
    }
}

void id_provisioner::third_callback(xtt::return_code rc,
                                    const xtt::identity& assigned_id,
                                    std::unique_ptr<xtt::longterm_key> clients_longterm_key,
                                    std::unique_ptr<xtt::pseudonym> clients_pseudonym,
                                    boost::asio::ip::tcp::socket /*tcp_socket*/)
{
    (void)clients_longterm_key;
    if (xtt::return_code::HANDSHAKE_FINISHED != rc) {
        std::cerr << "Error with final stage of handshake\n";
        // self now goes out of scope, releasing its memory (thus closing socket in handshake_)
        return;
    } else {
        std::cout << "Successfully finished handshake!\n";
        std::cout << "Client's pseudonym:       {" << clients_pseudonym->serialize_to_text() << "}\n";
        std::cout << "We assigned the identity: {" << assigned_id.serialize_to_text() << "}\n";
        std::cout << "Client has longterm key:  {" << clients_longterm_key->serialize_to_text() << "}\n";

    }

    // self and tcp_socket now go out of scope, releasing this memory and closing the socket
}
