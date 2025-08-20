from typing import Any, Dict

def flatten_dict(d: Dict[str, Any], parent_key: str = "", sep: str = ".") -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    def rec(obj, key_prefix):
        if isinstance(obj, dict):
            for k, v in obj.items():
                nk = f"{key_prefix}{sep}{k}" if key_prefix else str(k)
                rec(v, nk)
        elif isinstance(obj, list):
            # Para Excel, representamos listas como JSON compacta en una sola celda
            # Si se desea expandir índices, podría implementarse aquí.
            out[key_prefix] = obj
        else:
            out[key_prefix] = obj
    rec(d, parent_key)
    return out
