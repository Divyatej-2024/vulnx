def extract_cvss_vector(cvss_vector_str):
    # e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    parts = cvss_vector_str.split('/')
    mapping = {}
    for p in parts:
        if ':' in p:
            k, v = p.split(':',1)
            mapping[k] = v
    return mapping
