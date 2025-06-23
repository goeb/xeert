#ifndef HIERARCHY_H
#define HIERARCHY_H

#include <vector>

#include "certificate.h"

struct Certificate_with_links : public Certificate {
    std::string filename;
    int index_in_file;  // -1 if the file contains only 1 certificate
    std::set<Certificate_with_links*> parents;
    std::set<Certificate_with_links*> children;
    Certificate_with_links(const Certificate &cert):  Certificate(cert) {}
    std::string get_file_location() const;
};

bool is_self_signed(const Certificate_with_links &cert);
void compute_hierarchy(std::vector<Certificate_with_links> &certificates);

#endif
