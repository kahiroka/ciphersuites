# Cipher Suites Decorder

This is a complementary tool to Wireshark for decoding cipher suites of packet dump.
'ciphersuites.json' file, which is a cipher suites database, is derived from https://ciphersuite.info/.

# Usage

    $ python3 ciphersuites.py
    usage: python3 ciphersuites.py packet.bin

    $ python3 ciphersuites.py -b ftps-client-hello.bin 
    ['0xC0', '0x2C'] TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 ['TLS1.2'] Recommended
    ['0xC0', '0x30'] TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 ['TLS1.2'] Recommended
    ['0x00', '0x9F'] TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 ['TLS1.2'] Recommended
    ['0xC0', '0x2F'] TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 ['TLS1.2'] Recommended
    ['0xC0', '0x24'] TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 ['TLS1.2'] Secure
    ['0xC0', '0x28'] TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 ['TLS1.2'] Secure
    ['0x00', '0x6B'] TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 ['TLS1.2'] Secure
    ['0xC0', '0x23'] TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 ['TLS1.2'] Secure
    ['0xC0', '0x27'] TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 ['TLS1.2'] Secure
    ['0x00', '0x67'] TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 ['TLS1.2'] Secure
    ['0x00', '0x39'] TLS_DHE_RSA_WITH_AES_256_CBC_SHA ['TLS1.0', 'TLS1.1', 'TLS1.2'] Secure
    ['0x00', '0x9D'] TLS_RSA_WITH_AES_256_GCM_SHA384 ['TLS1.2'] Secure
    ['0x00', '0x3D'] TLS_RSA_WITH_AES_256_CBC_SHA256 ['TLS1.2'] Secure
    ['0x00', '0x3C'] TLS_RSA_WITH_AES_128_CBC_SHA256 ['TLS1.2'] Secure
    ['0x00', '0x2F'] TLS_RSA_WITH_AES_128_CBC_SHA ['TLS1.0', 'TLS1.1', 'TLS1.2'] Secure
    ['0x00', '0xFF'] TLS_EMPTY_RENEGOTIATION_INFO_SCSV ['TLS1.0'] None
