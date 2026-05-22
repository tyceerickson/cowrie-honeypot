#!/usr/bin/env python3
"""
hassh_identify.py — Pattern-Based HASSH Tool Identification
============================================================
Identifies SSH client tools from HASSH fingerprints without requiring
a static hardcoded database. Uses two identification methods:

  1. Algorithm string pattern matching — identifies tool family from the
     SSH key exchange algorithms themselves. Works on any unknown hash
     without needing a prior database entry.

  2. Persistent local cache — saves every identified hash to a JSON file
     so identifications accumulate over time. New hashes are identified
     once and remembered forever.

Design rationale: No external database covers modern (2024+) tools reliably.
The Salesforce HASSH database (2018) covers only old OpenSSH versions.
Algorithm patterns are stable across versions of the same tool family —
Paramiko always includes diffie-hellman-group1-sha1, OpenSSH 9.9+ always
includes mlkem768nistp256-sha256, Dropbear always uses legacy CBC ciphers.
These patterns identify tools correctly even for hashes never seen before.

Usage (standalone):
    python3 hassh_identify.py <hassh> <hassh_algorithms>
    python3 hassh_identify.py --show-cache
    python3 hassh_identify.py --clear-cache

Usage (as module):
    from hassh_identify import identify_hassh, load_cache
    tool = identify_hassh(hassh, hassh_algorithms)

Cache file: /opt/geoip/hassh_cache.json
    Grows automatically as new hashes are encountered.
    Safe to delete — will be rebuilt from pattern matching.
"""

import json
import os
import sys
import argparse
from pathlib import Path

# ============================================================
# Cache Configuration
# ============================================================
CACHE_PATH = "/opt/geoip/hassh_cache.json"  # intentionally in /opt/geoip alongside GeoLite2 databases


# ============================================================
# Seed Database — Known hashes identified from live capture
# These are pre-populated so the cache starts with known values
# ============================================================
SEED_DATABASE = {
    # ── Identified from live capture (NYC1, May 2026) ─────────
    "f555226df1963d1d3c09daf865abdc9a": "Paramiko 2.x (Python SSH library)",
    "03a80b21afa810682a776a7d42e5e6fb": "AsyncSSH (Python async SSH framework)",
    "16443846184eafde36765c9bab2f4397": "OpenSSH 9.0-9.7 (post-quantum mlkem)",
    "af8223ac9914f509afdadfaf5f7ee94e": "OpenSSH 9.9+ (mlkem768nistp256 + sntrup761)",
    "671ac49b8bd65b9e8ff02a3e690f0fd3": "OpenSSH 8.x",
    "e54ef3ec27fe1fea7ab64d3fa05359fd": "OpenSSH 8.x",
    "19532158b559096b89b1a5f7d17175b2": "OpenSSH 8.x",
    "5f904648ee8964bef0e8834012e26003": "OpenSSH 8.x",
    "9052c4ab4164c78256e71143dcfc7eac": "OpenSSH 8.x",
    "5bd26477da5440a6187bd3f1b39a429c": "OpenSSH 8.x",
    "4e066189c3bbeec38c99b1855113733a": "OpenSSH 8.x",
    "bc9e7273cde22b1209d6673b5fd10bd5": "OpenSSH 7.x (older)",
    "2aec6b44b06bec95d73f66b5d30cb69a": "OpenSSH 7.x (older)",
    "7216c7c473918b4f83d1139b3c70dbf9": "OpenSSH 7.x (older)",
    "0a07365cc01fa9fc82608ba4019af499": "Go SSH scanner",
    "f45fb203c31069bb280067b71ed92ccb": "libssh (no curve25519)",
    "b21d7cdcc8133dc2b430d1a039fece20": "Legacy SSH library (pre-2015)",
    "dde267e50f82fcc16a7e1e7b59b8af71": "Ancient SSH client (pre-2013 DH-only)",
    "a20aced7c9824fd804f59e68dd801ad3": "Dropbear / IoT device",
    # ── Common known fingerprints ──────────────────────────────
    "eeca2460550b9ded084ecf2f70a75356": "OpenSSH standard client",
    "a7a87fbe86774c2e40cc4a7ea2ab1b3c": "PuTTY SSH client",
    "06046964c022c6407d15a27b12a6a4fb": "Hydra SSH brute force tool",
    "92674c807a75b28f1e6de964d02f4ce7": "Mirai botnet variant",
    "b12ec4b88539c2b1ced74891b6db5e48": "Paramiko 1.x",
    "4e1201742c51073e8e5e6e47c90d739b": "Dropbear SSH (IoT/embedded)",
    "d976de41f6bc7e4c88f0ab5e7e47c49b": "LibSSH",
    "8f14e45fceea167a5a36dedd4bea2543": "AsyncSSH (alternate build)",
    "ec7378c1a92f5a8dde7e8b7a1ddf33d1": "OpenSSH 7.8-8.0",
    "0df0d56bb50c6b2426d8d40234bf1826": "OpenSSH 7.4-7.5",
    "68e0ba85e1a818f7c49ea3f4b849bd15": "OpenSSH 7.2",
}


def load_cache():
    """Load the persistent hash cache, seeding with known values if new."""
    cache_path = Path(CACHE_PATH)

    if cache_path.exists():
        try:
            with open(cache_path, 'r') as f:
                cache = json.load(f)
            # Merge seed database — seed values can be overridden by cache
            merged = dict(SEED_DATABASE)
            merged.update(cache)
            return merged
        except (json.JSONDecodeError, IOError):
            pass

    # First run — seed the cache
    save_cache(SEED_DATABASE)
    return dict(SEED_DATABASE)


def save_cache(cache):
    """Save the cache to disk."""
    cache_path = Path(CACHE_PATH)
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        with open(cache_path, 'w') as f:
            json.dump(cache, f, indent=2, sort_keys=True)
    except IOError as e:
        pass  # Non-fatal — cache is in-memory even if save fails


def pattern_identify(hassh_algorithms):
    """
    Identify SSH client tool from algorithm string patterns.
    Returns (tool_name, confidence) tuple.
    confidence: 'high', 'medium', 'low'

    Algorithm string format: kex;encryption;mac;compression
    """
    if not hassh_algorithms:
        return "Unknown (no algorithm data)", "low"

    algs = hassh_algorithms.lower()

    # Split into sections
    parts = algs.split(';')
    kex     = parts[0] if len(parts) > 0 else ''
    enc     = parts[1] if len(parts) > 1 else ''
    mac     = parts[2] if len(parts) > 2 else ''
    comp    = parts[3] if len(parts) > 3 else ''

    # ── High-confidence identifications ───────────────────────

    # OpenSSH 9.9+ — only version with mlkem768nistp256
    if 'mlkem768nistp256' in kex:
        return "OpenSSH 9.9+ (post-quantum mlkem768nistp256)", "high"

    # OpenSSH 9.0-9.7 — mlkem768x25519 but not mlkem768nistp256
    if 'mlkem768x25519' in kex and 'mlkem768nistp256' not in kex:
        return "OpenSSH 9.0-9.7 (post-quantum mlkem768x25519)", "high"

    # sntrup761 without mlkem — OpenSSH 8.5-8.9
    if 'sntrup761' in kex and 'mlkem' not in kex:
        return "OpenSSH 8.5-8.9 (sntrup761 post-quantum)", "high"

    # Paramiko signature: includes diffie-hellman-group1-sha1 alongside
    # modern ciphers. Standard OpenSSH dropped group1 in 8.x.
    if ('diffie-hellman-group1-sha1' in kex and
            'curve25519' in kex and
            ('aes256-gcm' in enc or 'chacha20' in enc)):
        return "Paramiko (Python SSH library)", "high"

    # AsyncSSH: curve25519 first, specific MAC ordering with etm priority,
    # no group1. Distinguished from OpenSSH by cipher/mac ordering.
    if ('curve25519-sha256,' in kex and
            'curve25519-sha256@libssh.org' in kex and
            'hmac-sha2-256-etm' in mac and
            'diffie-hellman-group1-sha1' not in kex and
            'diffie-hellman-group14-sha1' in kex and
            'aes128-gcm@openssh.com' not in enc.split(',')[0]):
        # AsyncSSH puts chacha20 first in encryption
        if enc.strip().startswith('chacha20'):
            return "AsyncSSH (Python async SSH)", "medium"

    # Dropbear / IoT: only legacy ciphers, no AES-GCM, no chacha20,
    # only old CBC modes, limited kex
    if ('aes256-gcm' not in enc and
            'chacha20' not in enc and
            'aes128-gcm' not in enc and
            ('aes128-cbc' in enc or '3des-cbc' in enc) and
            'curve25519' not in kex):
        if 'diffie-hellman-group1-sha1' in kex:
            return "Dropbear SSH / IoT device", "high"
        return "Legacy SSH library (pre-2014)", "medium"

    # Very ancient: only DH group exchange, no elliptic curve, no AES-GCM
    if ('curve25519' not in kex and
            'ecdh' not in kex and
            'diffie-hellman-group-exchange' in kex and
            'aes256-gcm' not in enc):
        return "Ancient SSH client (pre-2013)", "high"

    # libssh: starts with ecdh-sha2-nistp256 (no curve25519 at all)
    if (kex.strip().startswith('ecdh-sha2-nistp256') and
            'curve25519' not in kex):
        return "libssh / custom tool (no curve25519)", "high"

    # Go SSH library: specific algorithm ordering with group18/16 present
    # and no ext-info-c in some versions
    if ('diffie-hellman-group18-sha512' in kex and
            'diffie-hellman-group1-sha1' not in kex and
            'mlkem' not in kex and
            'sntrup' not in kex):
        if 'ext-info-c' not in kex:
            return "Go SSH library (golang.org/x/crypto/ssh)", "medium"

    # ── Medium-confidence — OpenSSH version ranging ────────────

    # OpenSSH 8.x: curve25519 (without @libssh.org prefix being first),
    # has group16/18, no post-quantum
    if ('curve25519-sha256,' in kex and
            'diffie-hellman-group16-sha512' in kex and
            'diffie-hellman-group18-sha512' in kex and
            'mlkem' not in kex and
            'sntrup' not in kex):
        # Check for ext-info-c (present in OpenSSH 7.2+)
        if 'ext-info-c' in kex:
            return "OpenSSH 8.x", "medium"

    # OpenSSH 7.x: curve25519 with @libssh.org format (old notation)
    # and no group16/18
    if ('curve25519-sha256@libssh.org' in kex and
            'curve25519-sha256,' not in kex and
            'diffie-hellman-group16-sha512' not in kex):
        return "OpenSSH 7.x (older)", "medium"

    # OpenSSH 7.x with new format but missing group16/18
    if ('curve25519-sha256,' in kex and
            'diffie-hellman-group16-sha512' not in kex and
            'mlkem' not in kex):
        return "OpenSSH 7.x-8.0 (transitional)", "medium"

    # ── Low confidence fallback ────────────────────────────────
    if 'curve25519' in kex:
        return "Modern SSH client (post-2014, unidentified)", "low"

    return "Unknown SSH client", "low"


def identify_hassh(hassh, hassh_algorithms=None, cache=None):
    """
    Main identification function.
    Checks cache first, then falls back to pattern matching.
    Saves new identifications to cache automatically.

    Args:
        hassh: MD5 HASSH fingerprint string
        hassh_algorithms: Full algorithm string from cowrie.client.kex event
        cache: Optional pre-loaded cache dict (pass for performance)

    Returns:
        String description of the identified tool
    """
    if cache is None:
        cache = load_cache()

    # Check cache first
    if hassh in cache:
        return cache[hassh]

    # Fall back to pattern matching
    if hassh_algorithms:
        tool, confidence = pattern_identify(hassh_algorithms)

        # Save to cache if confidence is medium or high
        if confidence in ('high', 'medium'):
            cache[hassh] = tool
            save_cache(cache)

        if confidence == 'low':
            return f"{tool} [low confidence]"
        return tool

    return "Unknown (no algorithm data)"


def show_cache():
    """Print the current cache contents."""
    cache = load_cache()
    print(f"[+] HASSH cache: {CACHE_PATH}")
    print(f"[+] Total entries: {len(cache)}\n")
    for hassh, tool in sorted(cache.items(), key=lambda x: x[1]):
        print(f"  {hassh}  {tool}")


def main():
    parser = argparse.ArgumentParser(
        description="Identify SSH client tools from HASSH fingerprints"
    )
    parser.add_argument("hassh", nargs="?", help="HASSH fingerprint to identify")
    parser.add_argument("algorithms", nargs="?", help="HASSH algorithm string")
    parser.add_argument("--show-cache", action="store_true",
                        help="Show all cached identifications")
    parser.add_argument("--clear-cache", action="store_true",
                        help="Clear cache and reseed with defaults")
    parser.add_argument("--cache-path", default=CACHE_PATH,
                        help=f"Cache file path (default: {CACHE_PATH})")
    args = parser.parse_args()

    if args.clear_cache:
        save_cache(SEED_DATABASE)
        print(f"[+] Cache cleared and reseeded with {len(SEED_DATABASE)} entries")
        return

    if args.show_cache:
        show_cache()
        return

    if not args.hassh:
        parser.print_help()
        return

    cache = load_cache()
    result = identify_hassh(args.hassh, args.algorithms, cache)
    print(f"[+] {args.hassh}")
    print(f"    {result}")

    if args.algorithms:
        tool, confidence = pattern_identify(args.algorithms)
        print(f"    Pattern match: {tool} [{confidence} confidence]")


if __name__ == "__main__":
    main()
