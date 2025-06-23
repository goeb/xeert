
#include "hierarchy.h"
#include "journal.h"
#include "oid_name.h"
#include "render_text.h"

std::string to_string(const Name &name)
{
    std::string result;
    bool start = true;
    for (auto relative_dn: name) {
        for (auto attribute: relative_dn) {
            if (!start) result += ", ";
            result += oid_get_name(attribute.type, true);
            result += ":";
            result += attribute.value;
            start = false;
        }
    }
    return result;
}

std::string to_string(bool boolean)
{
    if (boolean) return "true";
    else return "false";
}

std::string to_string(const BasicConstraints &basic_constraints)
{
    std::string result;
    result += "cA:" + to_string(basic_constraints.ca);
    if (!basic_constraints.path_len_constraint.empty()) {
        result += ", pathLenConstraint: " + basic_constraints.path_len_constraint;
    }
    return result;
}

std::string to_string(const OctetString &bytes)
{
    return hexlify(bytes);
}

std::string to_string(const AlgorithmIdentifier &algo)
{
    std::string result = oid_get_name(algo.algorithm);
    if (!algo.parameters.empty()) result += " (" + to_string(algo.parameters) + ")";
    return result;
}

std::string to_string(const std::set<std::string> &setstr, const std::string &separator)
{
    std::string result;
    std::set<std::string>::const_iterator it;
    for (it=setstr.begin(); it!=setstr.end(); it++) {
        if (it != setstr.begin()) {
            result += separator;
        }
        result += *it;
    }
    return result;
}

static std::string to_string(const GeneralNames &general_names)
{
    switch (general_names.type) {
    case GeneralNames::TYPE_STR:
        return general_names.stringvalue;
    case GeneralNames::TYPE_NAME:
        return to_string(general_names.namevalue);
    case GeneralNames::TYPE_OTHER:
        return to_string(general_names.othervalue);
    default:
        LOGERROR("Unexpected type of GeneralNames: %d", general_names.type);
        return "(error)";
    }
}

static std::string to_string(const AuthorityKeyIdentifier &akid)
{
    std::string result;
    if (!akid.key_identifier.empty()) {
        result += to_string(akid.key_identifier);
    }
    if (!akid.authority_cert_issuer.empty()) {
        if (!result.empty()) result += ", ";
        result += to_string(akid.authority_cert_issuer);
    }
    if (!akid.authority_cert_serial_number.empty()) {
        if (!result.empty()) result += ", ";
        result += "serial:" + akid.authority_cert_serial_number;
    }
    return result;
}

std::string to_string(const Extension &ext)
{
    std::string result;
    std::string oid_name = oid_get_name(ext.extn_id);
    if (oid_name == "id-ce-subjectKeyIdentifier") {
        SubjectKeyIdentifier skid = std::any_cast<SubjectKeyIdentifier>(ext.extn_value);
        return to_string(skid);
    } else if (oid_name == "id-ce-keyUsage") {
        KeyUsage key_usage = std::any_cast<KeyUsage>(ext.extn_value);
        return to_string(key_usage, "|");
    } else if (oid_name == "id-ce-privateKeyUsagePeriod") {
        OctetString value = std::any_cast<OctetString>(ext.extn_value);
        return to_string(value);
    } else if (oid_name == "id-ce-subjectAltName") {
        GeneralNames general_names = std::any_cast<GeneralNames>(ext.extn_value);
        return to_string(general_names);
    } else if (oid_name == "id-ce-issuerAltName") {
        GeneralNames general_names = std::any_cast<GeneralNames>(ext.extn_value);
        return to_string(general_names);
    } else if (oid_name == "id-ce-basicConstraints") {
        BasicConstraints basic_constraints = std::any_cast<BasicConstraints>(ext.extn_value);
        return to_string(basic_constraints);
    } else if (oid_name == "id-ce-cRLNumber") {
        OctetString value = std::any_cast<OctetString>(ext.extn_value);
        return to_string(value);
    } else if (oid_name == "id-ce-cRLReasons") {
        OctetString value = std::any_cast<OctetString>(ext.extn_value);
        return to_string(value);
    } else if (oid_name == "id-ce-instructionCode") {
        OctetString value = std::any_cast<OctetString>(ext.extn_value);
        return to_string(value);
    } else if (oid_name == "id-ce-holdInstructionCode") {
        OctetString value = std::any_cast<OctetString>(ext.extn_value);
        return to_string(value);
    } else if (oid_name == "id-ce-invalidityDate") {
        std::string value = std::any_cast<std::string>(ext.extn_value);
        return value;
    } else if (oid_name == "id-ce-issuingDistributionPoint") {
        OctetString value = std::any_cast<OctetString>(ext.extn_value);
        return to_string(value);
    } else if (oid_name == "id-ce-deltaCRLIndicator") {
        OctetString value = std::any_cast<OctetString>(ext.extn_value);
        return to_string(value);
    } else if (oid_name == "id-ce-issuingDistributionPoint") {
        OctetString value = std::any_cast<OctetString>(ext.extn_value);
        return to_string(value);
    } else if (oid_name == "id-ce-certificateIssuer") {
        GeneralNames general_names = std::any_cast<GeneralNames>(ext.extn_value);
        return to_string(general_names);
    } else if (oid_name == "id-ce-nameConstraints") {
        OctetString value = std::any_cast<OctetString>(ext.extn_value);
        return to_string(value);
    } else if (oid_name == "id-ce-cRLDistributionPoints") {
        OctetString value = std::any_cast<OctetString>(ext.extn_value);
        return to_string(value);
    } else if (oid_name == "id-ce-certificatePolicies") {
        OctetString value = std::any_cast<OctetString>(ext.extn_value);
        return to_string(value);
    } else if (oid_name == "id-ce-policyMappings") {
        OctetString value = std::any_cast<OctetString>(ext.extn_value);
        return to_string(value);
    } else if (oid_name == "id-ce-authorityKeyIdentifier") {
        AuthorityKeyIdentifier akid = std::any_cast<AuthorityKeyIdentifier>(ext.extn_value);
        return to_string(akid);
    } else if (oid_name == "id-ce-policyConstraints") {
        OctetString value = std::any_cast<OctetString>(ext.extn_value);
        return to_string(value);
    } else if (oid_name == "id-ce-extKeyUsage") {
        OctetString value = std::any_cast<OctetString>(ext.extn_value);
        return to_string(value);
    } else {
        OctetString value = std::any_cast<OctetString>(ext.extn_value);
        return to_string(value);
    }


    if (ext.critical) result += " (critical)";
    return result;
}

/*
 * Format a node for a rich tree:
 *
 * │ country:YY, cn:Root YY
 * │ 2025-04-25 20:03:10Z .. 2045-04-20 20:03:10Z
 * │ ca-root.crt
 * └──┬─────────────────────────────────────────────────────────────────
 *    ├──┤ country:YY, cn:ca-level1-a
 *    │  │ 2025-04-25 20:03:10Z .. 2045-04-20 20:03:10Z
 *    │  │ ca-level1-a.crt
 *    │  └──┬─────────────────────────────────────────────────────────────────
 *    │     ├──┤ country:YY, cn:ca-level2-a
 *    │     │  │ 2025-04-25 20:03:10Z .. 2045-04-20 20:03:10Z
 *    │     │  │ ca-level2-a.crt
 *    │     │  └────────────────────────────────────────────────────────────────────
 * ...
 */
static std::string to_rich_node(const Certificate_with_links &cert, const IndentationContext &indent_ctx)
{
    std::string result;
    size_t indent_level = indent_ctx.lineage.size();
    LOGDEBUG("indent_level=%lu", indent_level);
    std::string indent_first_line;
    std::string indent_second_lines;
    std::string indent_last_line;
    if (indent_level) {
        for (size_t i=0; i<indent_level-1; i++) {
            indent_first_line += indent_ctx.lineage[i]?"   │  ":"      ";
        }
        indent_second_lines = indent_first_line;
        indent_last_line = indent_first_line;
        // do the last step, where first and second lines differ
        if (indent_ctx.lineage[indent_level-1]) {
            indent_first_line   += "   ├──┤ ";
            indent_second_lines += "   │  │ ";
            indent_last_line    += "   │  └─";
        } else {
            indent_first_line   += "   └──┤ ";
            indent_second_lines += "      │ ";
            indent_last_line    += "      └─";
        }
    } else {
        // This certificate has no parent
        indent_first_line   = "│ ";
        indent_second_lines = "│ ";
        indent_last_line    = "└─";
    }
    result += indent_first_line + to_string(cert.tbs_certificate.subject) + "\n";
    if (is_self_signed(cert)) result += indent_second_lines + "self-signed\n";
    result += indent_second_lines + cert.tbs_certificate.validity.not_before + " .. " + cert.tbs_certificate.validity.not_after + "\n";
    result += indent_second_lines + cert.get_file_location() + "\n";
    if (!cert.children.empty()) {
        result += indent_last_line + "─┬─────────────────────────────────────────────────────────────────\n";
    } else {
        result += indent_last_line + "───────────────────────────────────────────────────────────────────\n";
    }

    // TODO extensions
    for (auto it: cert.tbs_certificate.extensions.items) {
        if (it.first == oid_get_id("id-ce-basicConstraints")) {
            BasicConstraints basic_constraints = std::any_cast<BasicConstraints>(it.second.extn_value);
            //printf("basicConstraints: %s\n", to_string(basic_constraints).c_str());
        }
    }
    return result;
}

/**
 * Format a node for a minimal tree:
 *
 * cn:Root YY (root.crt)
 * ├── cn:level1-a (level1-a.crt)
 * │   ├── cn:level2-a (level2-a.crt)
 * │   └── cn:level2-b (level2-b.crt)
 * │       └── cn:level3-a (level3-a.crt)
 * └── cn:level1-b (level1-b.crt)
 *     └── cn:level2-c (level2-c.crt)
 */
static std::string to_minimal_node(const Certificate_with_links &cert, const IndentationContext &indent_ctx)
{
    std::string result;
    size_t indent_level = indent_ctx.lineage.size();
    LOGDEBUG("indent_level=%lu", indent_level);
    std::string indent_line;
    if (indent_level) {
        for (size_t i=0; i<indent_level-1; i++) {
            indent_line += indent_ctx.lineage[i]?"│   ":"    ";
        }
        // do the last step, where first and second lines differ
        if (indent_ctx.lineage[indent_level-1]) {
            indent_line   += "├── ";
        } else {
            indent_line   += "└── ";
        }
    } else {
        // This certificate has no parent
        indent_line = "";
    }
    result += indent_line + to_string(cert.tbs_certificate.subject) + "(" + cert.get_file_location() + ")\n";

    return result;
}


static void print_tree(const Certificate_with_links &cert, IndentationContext indentation_ctx, bool minimal)
{
    if (minimal) printf("%s", to_minimal_node(cert, indentation_ctx).c_str());
    else printf("%s", to_rich_node(cert, indentation_ctx).c_str());

    std::set<Certificate_with_links*>::const_iterator child;
    for (child=cert.children.begin(); child!=cert.children.end(); child++) {
        std::set<Certificate_with_links*>::const_iterator next_child = child;
        next_child++;
        IndentationContext indentation_ctx_child = indentation_ctx;
        if (next_child== cert.children.end()) {
            // Last child
            indentation_ctx_child.lineage.push_back(false);
        } else {
            indentation_ctx_child.lineage.push_back(true);
        }
        print_tree(*(*child), indentation_ctx_child, minimal);
    }
}

/**
 * @brief Print a hierarchical tree of certificates
 *
 * For each certificate that has no parent, print its descendance.
 * It is assumed that:
 * - there is at least a certifictae that has no parent
 *   (circular dependencies have been broken)
 * - no certificate has 2 or more parents
 */
void print_tree(const std::vector<Certificate_with_links> &certificates, bool minimal)
{
    LOGINFO("Printing tree...");
    std::vector<Certificate_with_links>::const_iterator cert;
    IndentationContext indentation_ctx;
    for (cert=certificates.begin(); cert!=certificates.end(); cert++) {
        if (cert->parents.empty()) {
            print_tree(*cert, indentation_ctx, minimal);
        }
    }
}

static void print_property(const std::string &prefix, const char *name, const std::string &value)
{
    printf("%s%s: %s\n", prefix.c_str(), name, value.c_str());
}

void print_cert(const Certificate_with_links &certificate, bool single)
{
    Extensions extensions;
    std::string prefix;
    if (!single) prefix = certificate.get_file_location() + ": ";

    print_property(prefix, "subject", to_string(certificate.tbs_certificate.subject));
    print_property(prefix, "version", certificate.tbs_certificate.version);
    print_property(prefix, "serial", certificate.tbs_certificate.serial_number);
    print_property(prefix, "tbssignaturealgo", to_string(certificate.tbs_certificate.signature));
    print_property(prefix, "issuer", to_string(certificate.tbs_certificate.issuer));
    print_property(prefix, "notbefore", certificate.tbs_certificate.validity.not_before);
    print_property(prefix, "notafter", certificate.tbs_certificate.validity.not_after);
    print_property(prefix, "pubkeyalgo", to_string(certificate.tbs_certificate.subject_public_key_info.algorithm));
    print_property(prefix, "pubkeybytes", to_string(certificate.tbs_certificate.subject_public_key_info.subject_public_key));
    if (!certificate.tbs_certificate.issuer_unique_id.empty()) {
        print_property(prefix, "pubkeybytes", to_string(certificate.tbs_certificate.issuer_unique_id));
    }
    if (!certificate.tbs_certificate.subject_unique_id.empty()) {
        print_property(prefix, "pubkeybytes", to_string(certificate.tbs_certificate.subject_unique_id));
    }
    for (auto ext: certificate.tbs_certificate.extensions.items) {
        print_property(prefix, oid_get_name(ext.first, true).c_str(), to_string(ext.second));
    }
    print_property(prefix, "signaturealgo", to_string(certificate.signature_algorithm));
    print_property(prefix, "signaturebytes", to_string(certificate.signature_value));
}

