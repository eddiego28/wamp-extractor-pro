from __future__ import annotations
import json
import pandas as pd
from typing import Any, Dict, List, Optional
from .wamp_parser import normalize_wamp
from ..util.flatten import flatten

def normalize_rows(frames: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for f in frames:
        pt = f.get('payload_text')
        if not isinstance(pt, str):
            continue
        n = normalize_wamp(pt)
        if not n:
            continue
        # Columns
        row: Dict[str, Any] = {
            'time': None,
            'epoch': f.get('epoch'),
            'frame': f.get('frame_number'),
            'code': n['code'],
            'code_name': n['code_name'],
            'topic': n['topic'],
            'realm': n['realm'],
            'root_key': n['root_key'],
            'raw': json.dumps(n['raw_array'], ensure_ascii=False),
        }
        # derive time string
        if isinstance(row['epoch'], (float, int)):
            import datetime, math
            dt = datetime.datetime.utcfromtimestamp(float(row['epoch']))
            row['time'] = dt.strftime('%H:%M:%S.') + f"{int(dt.microsecond/1000):03d}"
        # flatten content (kwargs preferred)
        flat: Dict[str, Any] = {}
        content = n['content']
        if content is not None:
            from copy import deepcopy
            flatten('content', deepcopy(content), flat, max_list=20)
        row.update(flat)
        rows.append(row)
    return rows

def to_excel(frames: List[Dict[str, Any]], xlsx_path: str, topics: List[str], realms: List[str]) -> None:
    rows = normalize_rows(frames)
    df = pd.DataFrame(rows).sort_values(by=['epoch','frame'], na_position='last')
    # Summary sheets
    df_topics = pd.DataFrame({'topic': sorted(set([t for t in topics if t]))})
    df_realms = pd.DataFrame({'realm': sorted(set([r for r in realms if r]))})
    with pd.ExcelWriter(xlsx_path, engine='openpyxl') as writer:
        df.to_excel(writer, sheet_name='Messages', index=False)
        df_topics.to_excel(writer, sheet_name='Topics', index=False)
        df_realms.to_excel(writer, sheet_name='Realms', index=False)

def to_ndjson(frames: List[Dict[str, Any]], json_path: str) -> None:
    rows = normalize_rows(frames)
    with open(json_path, 'w', encoding='utf-8') as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + '\n')
