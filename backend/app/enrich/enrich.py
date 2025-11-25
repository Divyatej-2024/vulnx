def parse_cvss_vector(vector_str):
    if not vector_str:
        return {}
    parts = vector_str.split('/')
    mapping = {}
    for p in parts:
        if ':' in p:
            k, v = p.split(':', 1)
            mapping[k] = v
    return mapping
