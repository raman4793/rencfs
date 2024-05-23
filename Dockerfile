# Use an argument to specify the Ubuntu version, with a default
ARG UBUNTU_VERSION=20.04

# Use the specified Ubuntu version from the .env file
FROM ubuntu:${UBUNTU_VERSION}

#ARG USER_NAME=developer
#ARG USER_HOME=/home/developer
#ARG PROJECT_NAME=rencfs

#ENV USER_NAME=${USER_NAME}
#ENV USER_HOME=${USER_HOME}
#ENV PROJECT_NAME=${PROJECT_NAME}

#ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y curl git gcc build-essential fuse3
#RUN apt-get update && apt-get install -y \
#    git  \
#    curl \
#    gcc \
#    pkg-config \
#    build-essential \
#    fuse3

#RUN useradd -m -s /bin/bash -d ${USER_HOME} ${USER_NAME} \
#    && echo "${USER_NAME} ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/${USER_NAME} \
#    && chmod 0440 /etc/sudoers.d/${USER_NAME}

## Switch to the new user
#USER ${USER_NAME}
#WORKDIR ${USER_HOME}

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
RUN . ~/.cargo/env && rustup default nightly && rustup update

# Set the environment variables needed for Rust
ENV PATH="${USER_HOME}/.cargo/bin:${PATH}"

#WORKDIR ${USER_HOME}/${PROJECT_NAME}

# Build our actual code
COPY Cargo.toml Cargo.lock /usr/src/rencfs/
COPY src /usr/src/rencfs/src
COPY examples /usr/src/rencfs/examples
RUN . ~/.cargo/env &&  \
    cd /usr/src/rencfs/ &&  \
    cargo build --target x86_64-unknown-linux-musl --release

COPY /usr/src/rencfs/target/x86_64-unknown-linux-musl/release/rencfs /usr/local/bin

# Command to keep the container running
CMD ["rencfs", "--help"]
