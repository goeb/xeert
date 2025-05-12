#include <algorithm>
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

static void mark_issuer(Certificate_with_links &issuer, Certificate_with_links &issued)
{
    issuer.children.insert(&issued);
    issued.parents.insert(&issuer);
}

/**
 * @brief break_loop
 * @param loop  A list of nodes where node n+1 is child of node n
 *              and the first node is child of the last node.
 */
static void break_loop(std::list<Certificate_with_links*> &loop)
{
    std::list<Certificate_with_links*>::iterator it;
    std::list<Certificate_with_links*>::iterator target;

    assert(loop.size() >= 2);

    // Look for the relationship that should be destroyed
    // 1. if some visited nodes have more than 1 parent, target the one with the most parents
    // 2. else, if some visited nodes have more than 1 child, target the one with the most children
    // 3. else (all have exactly 1 parent and 1 child), arbitrarily target the first one

    // 1. Look for the node with the most parents
    target = loop.begin();
    for (it=loop.begin(); it!=loop.end(); it++) {
        if ((*it)->parents.size() > (*target)->parents.size()) {
            target = it;
        }
        LOGDEBUG("Cert %s has %lu parent(s)", (*it)->get_file_location().c_str(), (*it)->parents.size());
    }
    if ((*target)->parents.size() > 1) {
        // Eg: C -> B and A -> B -> C
        // => target=B has 2 parents => remove its parent that is also part of the loop (the previous in the list)
        Certificate_with_links *previous;
        if (target == loop.begin()) previous = loop.back();
        else previous = *(std::prev(target));
        LOGWARNING("Ignoring %s as a child of %s (circular dependency 1)",
                   (*target)->get_file_location().c_str(), previous->get_file_location().c_str());
        (*target)->parents.erase(previous);
        previous->children.erase(*target);
        return;
    }

    // 2. Look for the node with the most children
    target = loop.begin();
    for (it=loop.begin(); it!=loop.end(); it++) {
        if ((*it)->children.size() > (*target)->children.size()) {
            target = it;
        }
        LOGDEBUG("Cert %s has %lu children", (*it)->get_file_location().c_str(), (*it)->children.size());
    }
    if ((*target)->children.size() > 1) {
        // Eg: A -> B -> C -> A and B -> D
        // => target=B has 2 children => remove its child that is also part of the loop (the next in the list)
        it = std::next(target);
        if (it == loop.end()) it = loop.begin();
        Certificate_with_links *next = *it;
        LOGWARNING("Ignoring %s as a child of %s (circular dependency 2)",
                   next->get_file_location().c_str(), (*target)->get_file_location().c_str());
        (*target)->children.erase(next);
        next->parents.erase(*target);
    }

    // 3. Eg: A -> B -> C -> D -> A
    // => remove D -> A (the last 'A' is not part of the loop)
    Certificate_with_links *first = loop.front();
    Certificate_with_links *last = loop.back();
    LOGWARNING("Ignoring %s as a child of %s (circular dependency 2)",
               first->get_file_location().c_str(), last->get_file_location().c_str());
    first->parents.erase(last);
    last->children.erase(first);
}

static std::string loop_to_string(const std::list<Certificate_with_links*> &loop)
{
    std::string result;
    for (auto cert: loop) {
        if (!result.empty()) result += " -> ";
        result += cert->get_file_location();
    }
    // Close the loop
    result += " -> " + loop.front()->get_file_location();
    return result;
}

static std::list<Certificate_with_links*> find_loop(Certificate_with_links *cert, std::list<Certificate_with_links*> visited_nodes)
{
    std::list<Certificate_with_links*> loop; // empty if no loop found
    visited_nodes.push_back(cert);
    for (auto child: cert->children) {
        std::list<Certificate_with_links*>::iterator it = std::find(visited_nodes.begin(), visited_nodes.end(), child);
        if (it != visited_nodes.end()) {
            // Circular dependency detected
            loop = std::list<Certificate_with_links*>(it, visited_nodes.end());
            LOGINFO("Found loop: %s", loop_to_string(loop).c_str());
            break;
        } else {
            // Recurse into the child
            loop = find_loop(child, visited_nodes);
            if (!loop.empty()) break;
        }
    }
    return loop;
}

static void find_and_break_loops(std::vector<Certificate_with_links> &certs)
{
    for (auto cert: certs) {
        while (1) {
            std::list<Certificate_with_links*> visited_nodes;
            std::list<Certificate_with_links*> loop = find_loop(&cert, visited_nodes);
            if (loop.empty()) break;
            else break_loop(loop);
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
    LOGINFO("Computing tree of %lu certificates...", certs.size());
    // Remove duplicates
    prune_duplicates(certs);

    // Draw parent-child relationships
    std::vector<Certificate_with_links>::iterator cert1;
    std::vector<Certificate_with_links>::iterator cert2;
    for (cert1=certs.begin(); cert1!=certs.end(); cert1++) {
        for (cert2=cert1+1; cert2!=certs.end();) {
            if (is_issuer(*cert1, *cert2)) {
                // cert1 is parent of cert2
                mark_issuer(*cert1, *cert2);
            }
            if (is_issuer(*cert2, *cert1)) {
                // cert2 is parent of cert1
                mark_issuer(*cert2, *cert1);
            }
            cert2++;
        }
        LOGDEBUG("Cert %s has %lu parent(s)", cert1->get_file_location().c_str(), cert1->parents.size());

    }

    // Break circular loops
    find_and_break_loops(certs);

    // Remove multiple parents (eg: same authorities and keys, but different validity dates)
    // - in favor the the longest lineage
}
