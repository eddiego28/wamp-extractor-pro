from __future__ import annotations
import json
from typing import Any, Dict, List, Optional, Tuple

WAMP_CODES = {
    1: "HELLO",
    2: "WELCOME",
    3: "ABORT",
    4: "CHALLENGE",
    5: "AUTHENTICATE",
    6: "GOODBYE",
    7: "HEARTBEAT",
    8: "ERROR",
    16: "PUBLISH",
    17: "PUBLISHED",
    32: "SUBSCRIBE",
    33: "SUBSCRIBED",
    34: "UNSUBSCRIBE",
    35: "UNSUBSCRIBED",
    36: "EVENT",
    48: "CALL",
    49: "CANCEL",
    50: "RESULT",
}

def try_parse_json_array(text: str) -> Optional[List[Any]]:
    text = text.strip()
    if not (text.startswith("[") and text.endswith("]")):
        return None
    try:
        arr = json.loads(text)
        if isinstance(arr, list) and len(arr) >= 1 and isinstance(arr[0], int):
            return arr
    except Exception:
        return None
    return None

def extract_topic_from_publish(arr: List[Any]) -> Optional[str]:
    # [16, Request|id, Options|dict, Topic|uri, [Args], Kwargs]
    if len(arr) >= 4 and isinstance(arr[3], str):
        return arr[3]
    return None

def extract_topic_from_event(arr: List[Any]) -> Optional[str]:
    # [36, Subscription|id, Publication|id, Details|dict, [Args], Kwargs]
    # Topic may appear inside Details["topic"] sometimes (crossbar)
    if len(arr) >= 4 and isinstance(arr[3], dict):
        return arr[3].get("topic") or arr[3].get("Topic") or arr[3].get("topic_uri")
    return None

def extract_realm_from_hello(arr: List[Any]) -> Optional[str]:
    # WAMP HELLO: [1, Realm|uri, Details|dict] (v2)
    if len(arr) >= 2 and isinstance(arr[1], str):
        return arr[1]
    return None

def extract_args_kwargs(arr: List[Any]) -> Tuple[List[Any], Dict[str, Any]]:
    # As per WAMP spec, args is optional list and kwargs is optional dict at the end.
    args: List[Any] = []
    kwargs: Dict[str, Any] = {}
    # Heuristic: scan from the end
    tail = arr[1:]  # skip code at 0
    # Find last dict as kwargs if args present
    if len(tail) >= 1 and isinstance(tail[-1], dict):
        kwargs = tail[-1]
        tail = tail[:-1]
    if len(tail) >= 1 and isinstance(tail[-1], list):
        args = tail[-1]
    return args, kwargs

def detect_root_key(kwargs: Dict[str, Any]) -> Optional[str]:
    # If kwargs has a single high-level key (like EP / ER / etc.), return it
    if isinstance(kwargs, dict) and len(kwargs) == 1:
        return next(iter(kwargs))
    # else try a common payload field inside details
    return None

def normalize_wamp(text: str) -> Optional[Dict[str, Any]]:
    arr = try_parse_json_array(text)
    if not arr:
        return None
    code = arr[0]
    code_name = WAMP_CODES.get(code, f"UNKNOWN_{code}")
    topic = None
    realm = None
    if code == 16:
        topic = extract_topic_from_publish(arr)
    elif code == 36:
        topic = extract_topic_from_event(arr)
    elif code == 1:
        realm = extract_realm_from_hello(arr)
    args, kwargs = extract_args_kwargs(arr)
    root_key = detect_root_key(kwargs) if kwargs else None
    content = kwargs if kwargs else (args if args else None)
    return {
        "code": code,
        "code_name": code_name,
        "topic": topic,
        "realm": realm,
        "args": args,
        "kwargs": kwargs,
        "root_key": root_key,
        "raw_array": arr,
        "raw_text": text,
        "content": content,
    }
