#include <errno.h>
#include <fstream>
#include <iostream>
#include <limits.h>
#include <stdio.h>
#include <string.h>

#include "der_decode_x509.h"
#include "journal.h"
#include "load.h"
#include "util.h"

/* Read a PEM formatted certificate
 *
 * Returns:
 *    Bytes of the DER encoded certificate
 */
static OctetString get_pem_cert(std::istream &input)
{
    std::string line;
    std::getline(input, line);
    std::string base64lines, base64lines_tmp;
    if (line == "-----BEGIN CERTIFICATE-----") {

        // get all line until END
        while (getline(input, line)) {
            if (line == "-----END CERTIFICATE-----") {
                base64lines = base64lines_tmp;
                break;
            }
            else base64lines_tmp += line;
        }
        if (input.fail()) {
            LOGERROR("get_pem_cert: input error");
            return OctetString();
        }
    } else {
        LOGERROR("get_pem_cert: invalid first line");
        return OctetString();
    }
    // convert from base64
    OctetString bytes = base64_decode(base64lines);
    return bytes;
}

/* Read a PEM formatted certificate
 *
 * Returns:
 *    Bytes of the DER encoded certificate
 */
OctetString get_der_sequence(std::istream &input)
{
    OctetString der_bytes;

    // Get the length of the SEQUENCE (DER)
    // - either the first byt, if < 128
    // - or the following bytes (big endian)
    unsigned char buffer[2];
    input.read((char *)buffer, 2);
    if (!input.good()) {
        LOGERROR("Cannot get first 2 bytes of DER SEQUENCE: %s", strerror(errno));
        return OctetString();
    }
    der_bytes.append(buffer, 2);
    int data_length = 0;
    if (buffer[1] & 0x80) {
        // Length encoded on multibytes, big-endian
        int n_bytes = (unsigned char)buffer[1] & 0x7f;
        for (int i=0; i<n_bytes; i++) {
            unsigned char c;
            input.read((char*)&c, 1);
            if (!input.good()) {
                LOGERROR("Cannot get next byte of DER SEQUENCE: %s", strerror(errno));
                return OctetString();
            }
            if (data_length > (INT_MAX >> 8 )) {
                // unsigned integer overflow
                LOGERROR("Length of DER SEQUENCE overflow");
                return OctetString();
            }
            der_bytes.append(&c, 1);
            data_length = (data_length << 8) + (unsigned char)c;
        }
    } else {
        data_length = (unsigned char)buffer[1];
    }

    // Read the SEQUENCE contents
    unsigned char *contents = (unsigned char*)malloc(data_length);
    input.read((char *)contents, data_length);
    if (!input.good()) {
        LOGERROR("Cannot get %d bytes of contents DER SEQUENCE: %s", data_length, strerror(errno));
        free(contents);
        return OctetString();
    }
    der_bytes.append(contents, data_length);
    free(contents);

    return der_bytes;
}

static int load_cert_file(std::istream &input, const char *filename, std::vector<Certificate_with_links> &certificates)
{
    LOGDEBUG("%s", filename);
    size_t index = 0;
    while (1) {
        int c = input.peek();
        if (c == EOF) {
            // Cannot get a character
            if (input.eof()) break;
            LOGERROR("Cannot get first character: %s:%lu: %s", filename, index, strerror(errno));
            return -1;
        }
        OctetString der_bytes;
        if (c == '-') {
            LOGINFO("Loading %s:%lu as PEM", filename, index);
            der_bytes = get_pem_cert(input);
        } else if (c == 0x30) {
            LOGINFO("Loading %s:%lu as DER", filename, index);
            der_bytes = get_der_sequence(input);
        } else {
            LOGERROR("Unknown certificate format: %s:%lu", filename, index);
            return -1;
        }
        if (der_bytes.empty()) {
            LOGERROR("Could not read PEM/DER: %s:%lu", filename, index);
            return -1;
        }

        Certificate cert;
        int err = der_decode_x509_certificate(der_bytes, cert);

        if (err) {
            LOGERROR("Cannot decode certificate: %s:%lu", filename, index);
            return -1;
        }
        Certificate_with_links certificate(cert);
        certificate.filename = filename;
        certificate.index_in_file = index;
        certificates.push_back(certificate);
        index++;
    }

    if (certificates.empty()) {
        LOGWARNING("No certificate read from '%s'", filename);
    }

    return 0;
}

int load_certificates(const std::list<std::string> &paths, std::vector<Certificate_with_links> &certificates)
{
    int err;
    if (paths.size() == 0) {
        // Take certificates from stdin
        err = load_cert_file(std::cin, "(stdin)", certificates);
        if (certificates.size() == 1) {
            certificates[0].index_in_file = -1;
        }

    } else {
        for (auto cert_path : paths) {
            std::ifstream ifs(cert_path, std::ifstream::in);
            if (!ifs.good()) {
                LOGERROR("Cannot read from '%s': %s", cert_path.c_str(), strerror(errno));
                err = -1;
                break;
            } else {
                std::vector<Certificate_with_links> tmpcert;
                err = load_cert_file(ifs, cert_path.c_str(), tmpcert);
                if (err) break;
                if (tmpcert.size() == 1) {
                    tmpcert[0].index_in_file = -1;
                }
                certificates.insert(certificates.end(), tmpcert.begin(), tmpcert.end());
                ifs.close();
            }
        }
    }
    return err;
}
