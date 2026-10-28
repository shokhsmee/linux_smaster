#!/bin/bash
# Stand-in for the `docker` CLI inside the test container (Docker-in-Docker is
# impractical there). Answers the four subcommands the containers module uses
# with canned JSON describing one deliberately misconfigured container and one
# image with a key baked into ENV and a build ARG in its history.
case "$1 $2" in
    "ps -q")        echo "c0ffee000001" ;;
    "images -q")    echo "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" ;;
    "history --no-trunc")
        printf '/bin/sh -c #(nop) ARG AWS_SECRET_ACCESS_KEY=%s\n/bin/sh -c apt-get update\n' "$(printf 'C%.0s' $(seq 40))" ;;
    "inspect c0ffee000001")
        cat <<JSON
[{"Id": "c0ffee000001deadbeef", "Name": "/api",
  "Config": {"Image": "myapp:latest", "User": "",
             "Env": ["PATH=/usr/bin", "OPENAI_API_KEY=sk-proj-$(printf 'A%.0s' $(seq 48))", "DEBUG=1"]},
  "HostConfig": {"Privileged": true, "NetworkMode": "bridge", "PidMode": "", "UsernsMode": "",
                 "Binds": ["/var/run/docker.sock:/var/run/docker.sock", "/data:/data"], "CapAdd": null},
  "Mounts": [{"Type": "bind", "Source": "/var/run/docker.sock", "Destination": "/var/run/docker.sock"}]}]
JSON
        ;;
    "inspect sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        cat <<JSON
[{"Id": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "RepoTags": ["myapp:1.2"],
  "Config": {"Env": ["HF_TOKEN=hf_$(printf 'b%.0s' $(seq 34))"]}}]
JSON
        ;;
    *) echo "fake docker: unsupported arguments: $*" >&2; exit 1 ;;
esac
