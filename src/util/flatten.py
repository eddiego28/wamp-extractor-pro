from __future__ import annotations
from typing import Any, Dict, List

def flatten(prefix: str, obj: Any, out: Dict[str, Any], max_list: int = 10) -> None:
    """Flatten dict/list scalars into columns.
    Lists keep up to max_list items as prefix_i. Dicts recurse.
    """
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            flatten(key, v, out, max_list=max_list)
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:max_list]):
            key = f"{prefix}[{i}]" if prefix else f"[{i}]"
            flatten(key, v, out, max_list=max_list)
        if len(obj) > max_list:
            out[f"{prefix}._truncated"] = len(obj) - max_list
    else:
        out[prefix] = obj
