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

# softhsm is required for tests
install_from_github opendnssec SoftHSMv2 develop
