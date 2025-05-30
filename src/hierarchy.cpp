#include <assert.h>

#include "hierarchy.h"
#include "journal.h"
#include "oid_name.h"
#include "x509_verify.h"

std::string Certificate_with_links::get_file_location() const
{
    if (index_in_file < 0) return filename;
    return filename + ":" + std::to_string(index_in_file);
}


/**
 * @brief is_issuer
 * @param cert_issuer
 * @param cert_child
 * @return
 *
 * Tell if a certificate is a valid issuer of another certificate.
 *
 * - compare issuer/subject properties
 * - compare extensions
 * - verify signature
 */
static bool is_issuer(const Certificate_with_links &cert_issuer, const Certificate_with_links &cert_child)
{
    if (cert_issuer.tbs_certificate.subject != cert_child.tbs_certificate.issuer) {
        return false;
    }

    // Look if subjectKeyIdentifier and authorityKeyIdentifier match
    auto it = cert_child.tbs_certificate.extensions.items.find(oid_get_id("id-ce-authorityKeyIdentifier"));
    if (it != cert_child.tbs_certificate.extensions.items.end()) {
        // Extension authorityKeyIdentifier found in the child
        AuthorityKeyIdentifier akid = std::any_cast<AuthorityKeyIdentifier>(it->second.extn_value);
        if (akid.key_identifier.size()) {
            auto skidit = cert_issuer.tbs_certificate.extensions.items.find(oid_get_id("id-ce-subjectKeyIdentifier"));
            if (skidit == cert_issuer.tbs_certificate.extensions.items.end()) {
                // The issuer has no subjectKeyIdentifier
                LOGINFO("Issuer with no subjectKeyIdentifier (issuer %s, child %s)",
                        cert_issuer.get_file_location().c_str(),
                        cert_child.get_file_location().c_str());
                return false;
            }
            SubjectKeyIdentifier skid = std::any_cast<SubjectKeyIdentifier>(skidit->second.extn_value);
            if (skid != akid.key_identifier) {
                // Non-matching authorityKeyIdentifier/subjectKeyIdentifier
                LOGINFO("Issuer with different subjectKeyIdentifier (issuer %s, child %s)",
                        cert_issuer.get_file_location().c_str(),
                        cert_child.get_file_location().c_str());
                return false;
            }
        }
    }

    // Verify signature
    if (!x509_verify_signature(cert_issuer, cert_child)) {
        LOGERROR("Claimed child %s not verified by authority certificate %s",
                 cert_child.get_file_location().c_str(),
                 cert_issuer.get_file_location().c_str());
        return false;
    }

    return true;
}

static bool is_self_signed(const Certificate_with_links &cert)
{
    return is_issuer(cert, cert);
}

static void prune_duplicates(std::vector<Certificate_with_links> &certificates)
{
    std::vector<Certificate_with_links>::iterator cert1;
    std::vector<Certificate_with_links>::iterator cert2;
    for (cert1=certificates.begin(); cert1!=certificates.end(); cert1++) {
        for (cert2=cert1+1; cert2!=certificates.end();) {
            if (cert1->der_bytes == cert2->der_bytes) {
                // Same certificates. Remove the second
                LOGWARNING("Duplicate certificate %s:%lu ignored (same as %s:%lu)",
                           cert2->filename.c_str(), cert2->index_in_file,
                           cert1->filename.c_str(), cert1->index_in_file);
                cert2 = certificates.erase(cert2);
            } else {
                cert2++;
            }
        }
    }
}

/**
 * - Remove duplicates
 * - Draw parent-child relationships
 * - Break circular loops
 * - Remove multiple parents (eg: same authorities and keys, but different validity dates)
 */
void compute_hierarchy(std::vector<Certificate_with_links> &certs)
{
    // Remove duplicates
    prune_duplicates(certs);

    // Draw parent-child relationships
    std::vector<Certificate_with_links>::iterator cert1;
    std::vector<Certificate_with_links>::iterator cert2;
    for (cert1=certs.begin(); cert1!=certs.end(); cert1++) {
        for (cert2=cert1+1; cert2!=certs.end();) {
            if (is_issuer(*cert1, *cert2)) {
                // cert1 is parent of cert2
                cert1->children.push_back(&*cert2);
                cert2->parents.push_back(&*cert1);
            }
            if (is_issuer(*cert2, *cert1)) {
                // cert2 is parent of cert1
                cert2->children.push_back(&*cert1);
                cert1->parents.push_back(&*cert2);
            }
            cert2++;
        }
    }

    // Break circular loops
    // - in favor the the longest lineage

    // Remove multiple parents (eg: same authorities and keys, but different validity dates)
    // - in favor the the longest lineage
}
