from __future__ import annotations
from .app import Controller

def main():
    c = Controller()
    raise SystemExit(c.run())

if __name__ == '__main__':
    main()
