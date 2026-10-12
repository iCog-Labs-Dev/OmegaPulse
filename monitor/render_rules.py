"""Render Falco rules with the same validated target as the monitor."""
import argparse
import json
import os
from pathlib import Path

from .config import container_name


def render(template: str, target: str) -> str:
    target = container_name(target.strip())
    if template.count('__OMA_MONITOR_CONTAINER__') != 1:
        raise ValueError('Rules template must contain exactly one target placeholder')
    return template.replace('__OMA_MONITOR_CONTAINER__', json.dumps(target))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('template', type=Path)
    parser.add_argument('destination', type=Path)
    args = parser.parse_args()
    rules = render(args.template.read_text(), os.environ.get('OMA_MONITOR_CONTAINER', 'omega'))
    args.destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    args.destination.write_text(rules)


if __name__ == '__main__':
    main()
