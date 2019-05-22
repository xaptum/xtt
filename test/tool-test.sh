#!/bin/bash

set -e

if [[ $# -ne 3 ]]; then
        echo "usage: $0 <tool directory> <data directory> <tmp directory>"
        exit 1
fi

tool_dir="$1"
data_dir="$2"
tmp_dir="$3"
server_pid=-1

function cleanup()
{
        if [[ $server_pid -gt 0 ]]; then
                kill $server_pid
        fi
}
trap cleanup INT KILL EXIT

echo "Generating root keys..."
${tool_dir}/xtt genkeypair -k ${tmp_dir}/root_keys.asn1.bin

echo "Generating server keys..."
${tool_dir}/xtt genkeypair -k ${tmp_dir}/server_keys.asn1.bin

echo "Generating root certificate..."
${tool_dir}/xtt genrootcert -k ${tmp_dir}/root_keys.asn1.bin -c ${tmp_dir}/root_cert.bin

echo "Generating server certificate..."
${tool_dir}/xtt genservercert -r ${tmp_dir}/root_cert.bin -k ${tmp_dir}/root_keys.asn1.bin \
        -s ${tmp_dir}/server_keys.asn1.bin -c server_cert.bin

echo "Starting server..."
${tool_dir}/xtt runserver -d ${data_dir}/daa_gpk.bin -b ${data_dir}/basename.bin -k \
        ${tmp_dir}/server_keys.asn1.bin -c server_cert.bin &
server_pid=$!

sleep 1

if kill -0 "$server_pid" 2>/dev/null; then
        echo "Running client..."
        ${tool_dir}/xtt runclient -d ${data_dir}/daa_gpk.bin -c ${data_dir}/daa_cred.bin \
                -k ${data_dir}/daa_secretkey.bin -n ${data_dir}/basename.bin -e ${tmp_dir}/root_cert.bin
else
        echo "Error starting server. Quitting test..."
        server_pid=-1
        exit 1
fi
