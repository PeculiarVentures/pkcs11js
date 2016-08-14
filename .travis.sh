#!/bin/sh
set -e

install_from_github() {
    echo "Installing $2"
    git clone https://github.com/$1/$2.git -b $3
    cd $2
    autoreconf -fvi
    ./configure
    make
    sudo -E make install
    cd ..
    echo "$2 installed"
    sudo ldconfig
}

# prepare the softhsm configuration scripts
if [[ "$TRAVIS_OS_NAME" == "linux" ]]; then
    sudo apt-get update -qq
    sudo apt-get install libssl-dev
    sudo apt-get install autoconf -y
    sudo apt-get install automake -y
    sudo apt-get install libtool -y
    
elif [[ "$TRAVIS_OS_NAME" == "osx" ]]; then
    brew update
    brew install automake
    brew install openssl
    
    # seems to be needed
    export OPENSSL_INCLUDE_DIR=`brew --prefix openssl`/include
    export OPENSSL_LIB_DIR=`brew --prefix openssl`/lib
    brew link openssl --force
    
    brew install sqlite
    brew install cppunit
    
fi

# softhsm is required for tests
install_from_github opendnssec SoftHSMv2 develop

# initializing token
softhsm2-util --init-token --so-pin "12345" --pin "12345" --slot 0 --label "My slot 0"
