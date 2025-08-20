from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

@dataclass
class WampMessage:
    time_epoch: float
    time_text: str
    stream: str
    type_code: int
    type_name: str
    topic: Optional[str] = None
    realm: Optional[str] = None
    subscription_id: Optional[int] = None
    publication_id: Optional[int] = None
    request_id: Optional[int] = None
    details: Dict[str, Any] = field(default_factory=dict)
    args: List[Any] = field(default_factory=list)
    kwargs: Dict[str, Any] = field(default_factory=dict)
    raw_text: str = ""
    src: Optional[str] = None
    dst: Optional[str] = None
