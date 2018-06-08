#include <xtt.h>

#include "network_array.h"
#include "server_setup.h"
#include "client_setup.h"

void client_write_to_network(struct xtt_client_ctxhelper* client, struct network_helper* network);
void client_read_from_network(struct xtt_client_ctxhelper* client, struct network_helper* network);
void server_write_to_network(struct xtt_server_ctxhelper* server, struct network_helper* network);
void server_read_from_network(struct xtt_server_ctxhelper* server, struct network_helper* network);

void client_step_one(struct xtt_client_ctxhelper* client, struct network_helper* network);
void server_step_one(struct xtt_server_ctxhelper* server, struct network_helper* network);
void client_step_two(struct xtt_client_ctxhelper* client, struct network_helper* network);
void server_step_two(struct xtt_server_ctxhelper* server, xtt_group_id* cgid, struct network_helper* network, xtt_identity_type* client_id);
void client_step_three(struct xtt_client_ctxhelper* client, struct network_helper* network);

void handshake_checks(struct xtt_client_ctxhelper* client, struct xtt_server_ctxhelper* server, xtt_identity_type *client_id);

int main(int argc, char* argv[])
{
    TEST_ASSERT(argc > 1);

    struct xtt_client_ctxhelper client;
    struct xtt_server_ctxhelper server;
    struct network_helper network;
    setupNetwork(&network);

    xtt_identity_type client_id = {.data = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}};
    client.version = XTT_VERSION_ONE;
    client.suite_spec= (xtt_suite_spec)atoi(argv[1]);
    printf("Suite Spec: %d\n", client.suite_spec);

    setup_server_input(&server);
    setup_client_input(&client);
    client_step_one(&client, &network);
    server_step_one(&server, &network);
    client_step_two(&client, &network);
    server_step_two(&server, &client.gid, &network, &client_id);
    client_step_three(&client, &network);
    handshake_checks(&client, &server, &client_id);

}

void client_step_one(struct xtt_client_ctxhelper* client, struct network_helper* network){
    client->rc = xtt_handshake_client_start(&client->bytes_requested, &client->io_ptr, &client->ctx);
    EXPECT_EQ(client->rc, XTT_RETURN_WANT_WRITE);
    client_write_to_network(client, network);
    EXPECT_EQ(client->rc, XTT_RETURN_WANT_READ);
    printf("Passes all of client step 1\n");
}

void server_step_one(struct xtt_server_ctxhelper* server, struct network_helper* network){
    server->rc=xtt_handshake_server_handle_connect(&server->bytes_requested, &server->io_ptr, &server->ctx);
    EXPECT_EQ(server->rc, XTT_RETURN_WANT_READ);
    server_read_from_network(server, network);
    EXPECT_EQ(server->rc, XTT_RETURN_WANT_READ);
    server_read_from_network(server, network);
    EXPECT_EQ(server->rc, XTT_RETURN_WANT_BUILDSERVERATTEST);
    server->rc = xtt_handshake_server_build_serverattest(&server->bytes_requested, &server->io_ptr, &server->ctx, &server->cert_ctx, &server->cookie_ctx);
    EXPECT_EQ(server->rc, XTT_RETURN_WANT_WRITE);
    server_write_to_network(server, network);
    EXPECT_EQ(server->rc, XTT_RETURN_WANT_READ);
    printf("Passes all of server step 1\n");
}

void client_step_two(struct xtt_client_ctxhelper* client, struct network_helper* network){
    xtt_certificate_root_id claimed_root_out;
    const xtt_identity_type intended_server_id = {.data = {0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x30, 0x30, 0x30, 0x31}};

    client_read_from_network(client, network);
    EXPECT_EQ(client->rc, XTT_RETURN_WANT_READ);
    client_read_from_network(client, network);
    EXPECT_EQ(client->rc, XTT_RETURN_WANT_PREPARSESERVERATTEST);
    client->rc=xtt_handshake_client_preparse_serverattest(&claimed_root_out,
                                                    &client->bytes_requested,
                                                    &client->io_ptr,
                                                    &client->ctx);

    TEST_ASSERT(0 == memcmp(client->roots_id.data, claimed_root_out.data, sizeof(xtt_certificate_root_id)));
    EXPECT_EQ(client->rc, XTT_RETURN_WANT_BUILDIDCLIENTATTEST);
    client->rc=xtt_handshake_client_build_idclientattest(&client->bytes_requested, &client->io_ptr,
                                                    &client->server_root_cert, &xtt_null_identity,
                                                    &intended_server_id, &client->group_ctx,
                                                    &client->ctx);
    EXPECT_EQ(client->rc, XTT_RETURN_WANT_WRITE);
    client_write_to_network(client, network);
    EXPECT_EQ(client->rc, XTT_RETURN_WANT_READ);
    printf("Passes all of client step 2\n");
}

void server_step_two(struct xtt_server_ctxhelper* server, xtt_group_id* cgid, struct network_helper* network, xtt_identity_type *client_id){
    xtt_identity_type requested_client_id_out;
    xtt_group_id claimed_group_id_out;
    server_read_from_network(server, network);
    EXPECT_EQ(server->rc, XTT_RETURN_WANT_READ);
    server_read_from_network(server, network);
    EXPECT_EQ(server->rc, XTT_RETURN_WANT_PREPARSEIDCLIENTATTEST);
    server->rc=xtt_handshake_server_preparse_idclientattest(&server->bytes_requested,
                                                        &server->io_ptr,
                                                        &requested_client_id_out,
                                                        &claimed_group_id_out,
                                                        &server->cookie_ctx,
                                                        &server->cert_ctx,
                                                        &server->ctx);
    TEST_ASSERT(0 == memcmp(&requested_client_id_out, &xtt_null_identity, sizeof(requested_client_id_out)));
    TEST_ASSERT(0 == memcmp(&claimed_group_id_out, cgid, sizeof(xtt_certificate_root_id)));
    EXPECT_EQ(server->rc, XTT_RETURN_WANT_VERIFYGROUPSIGNATURE);
    server->rc = xtt_handshake_server_verify_groupsignature(&server->bytes_requested,
                                                        &server->io_ptr,
                                                        &server->group_pub_key_ctx,
                                                        &server->cert_ctx,
                                                        &server->ctx);
    EXPECT_EQ(server->rc, XTT_RETURN_WANT_BUILDIDSERVERFINISHED);
    server->rc = xtt_handshake_server_build_idserverfinished(&server->bytes_requested,
                                                        &server->io_ptr,
                                                        client_id,
                                                        &server->ctx);
    EXPECT_EQ(server->rc, XTT_RETURN_WANT_WRITE);
    server_write_to_network(server, network);
    EXPECT_EQ(server->rc, XTT_RETURN_HANDSHAKE_FINISHED);
    printf("Passes all of server step 2\n");
}

void client_step_three(struct xtt_client_ctxhelper* client, struct network_helper* network){
    client_read_from_network(client, network);
    EXPECT_EQ(client->rc, XTT_RETURN_WANT_READ);
    client_read_from_network(client, network);
    EXPECT_EQ(client->rc, XTT_RETURN_WANT_PARSEIDSERVERFINISHED);
    client->rc=xtt_handshake_client_parse_idserverfinished(&client->bytes_requested, &client->io_ptr, &client->ctx);
    EXPECT_EQ(client->rc, XTT_RETURN_HANDSHAKE_FINISHED);
    printf("Passes all of client step 3\n");
}


void client_write_to_network(struct xtt_client_ctxhelper* client, struct network_helper* network){
    clear_bytes(network);
    uint16_t bytes_to_write = client->bytes_requested;
    write_bytes(network, bytes_to_write, client->io_ptr);
    client->rc = xtt_handshake_client_handle_io(bytes_to_write, 0, &client->bytes_requested, &client->io_ptr, &client->ctx);
}

void client_read_from_network(struct xtt_client_ctxhelper* client, struct network_helper* network){
    uint16_t bytes_to_read = client->bytes_requested;
    read_bytes(network, bytes_to_read, client->io_ptr);
    client->rc = xtt_handshake_client_handle_io(0, bytes_to_read, &client->bytes_requested, &client->io_ptr, &client->ctx);
}

void server_write_to_network(struct xtt_server_ctxhelper* server, struct network_helper* network){
    clear_bytes(network);
    uint16_t bytes_to_write = server->bytes_requested;
    write_bytes(network, bytes_to_write, server->io_ptr);
    server->rc = xtt_handshake_server_handle_io(bytes_to_write, 0, &server->bytes_requested, &server->io_ptr, &server->ctx);
}

void server_read_from_network(struct xtt_server_ctxhelper* server, struct network_helper* network){
    uint16_t bytes_to_read = server->bytes_requested;
    read_bytes(network, bytes_to_read, server->io_ptr);
    server->rc = xtt_handshake_server_handle_io(0, bytes_to_read, &server->bytes_requested, &server->io_ptr, &server->ctx);
}

void handshake_checks(struct xtt_client_ctxhelper* client, struct xtt_server_ctxhelper* server, xtt_identity_type *client_id){
    xtt_version version_check;
    server->rc = xtt_get_version(&version_check, &server->ctx);
    EXPECT_EQ(XTT_RETURN_SUCCESS, server->rc);
    EXPECT_EQ(version_check, client->version);
    xtt_suite_spec suite_spec_check;
    server->rc = xtt_get_suite_spec(&suite_spec_check, &server->ctx);
    EXPECT_EQ(XTT_RETURN_SUCCESS, server->rc);
    EXPECT_EQ(suite_spec_check, client->suite_spec);

    xtt_identity_type assigned_id;
    client->rc = xtt_get_my_identity(&assigned_id, &client->ctx);
    EXPECT_EQ(XTT_RETURN_SUCCESS, client->rc);
    TEST_ASSERT(0 == memcmp(&assigned_id.data, &client_id->data, sizeof(xtt_identity_type)));

    xtt_ed25519_pub_key clients_longterm_key;
    server->rc = xtt_get_clients_longterm_key_ed25519(&clients_longterm_key, &server->ctx);
    EXPECT_EQ(XTT_RETURN_SUCCESS, server->rc);
    xtt_ed25519_pub_key my_longterm_key;
    client->rc = xtt_get_my_longterm_key_ed25519(&my_longterm_key, &client->ctx);
    EXPECT_EQ(XTT_RETURN_SUCCESS, client->rc);
    TEST_ASSERT(0 == memcmp(my_longterm_key.data, clients_longterm_key.data, sizeof(xtt_ed25519_pub_key)));

    xtt_daa_pseudonym_lrsw pseudonym_out;
    server->rc = xtt_get_clients_pseudonym_lrsw(&pseudonym_out, &server->ctx);
    EXPECT_EQ(XTT_RETURN_SUCCESS, server->rc);

    xtt_ed25519_priv_key longterm_key_priv_out;
    client->rc = xtt_get_my_longterm_private_key_ed25519(&longterm_key_priv_out, &client->ctx);
    EXPECT_EQ(XTT_RETURN_SUCCESS, client->rc);
}
