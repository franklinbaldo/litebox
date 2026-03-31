#!/usr/bin/env python3
"""Count words in the last N git commit messages."""

import subprocess
import sys
from collections import Counter


def get_commit_messages(n=5):
    result = subprocess.run(
        ["git", "log", f"-{n}", "--format=%s"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"Error: {result.stderr.strip()}", file=sys.stderr)
        sys.exit(1)
    return result.stdout.strip().splitlines()


def count_words(messages):
    counter = Counter()
    for msg in messages:
        counter.update(msg.split())
    return counter


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    messages = get_commit_messages(n)

    print(f"Last {n} commit messages:\n")
    for i, msg in enumerate(messages, 1):
        print(f"  {i}. {msg}")

    words = count_words(messages)
    total = sum(words.values())

    print(f"\nTotal words: {total}")
    print(f"Unique words: {len(words)}")
    print("\nWord frequencies (descending):")
    for word, count in words.most_common():
        print(f"  {word:30s} {count}")


if __name__ == "__main__":
    main()
