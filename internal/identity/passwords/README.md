Offline breached-password denylist, NCSC top-100k corpus, from SecLists (MIT):
https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt
Retrieved 2026-10-21. Source SHA-256: `c2e5696882c603b76bb67a47ee970897e5a76fc4c3f5547abe3d0ca340c576e0`.
The published file has 99840 lines; 97747 distinct case-folded entries.
`ncsc.bin` contains sorted 128-bit SHA-256 prefixes of the UTF-8 lowercase passwords.
Runtime lookup uses binary search over embedded bytes; no network, plaintext corpus,
or per-entry heap allocation. Accidental prefix collisions only reject a password.
To regenerate: hash each stripped/lowercased nonempty source line with SHA-256,
take the first 16 bytes, deduplicate, sort lexicographically and concatenate.
License: https://github.com/danielmiessler/SecLists/blob/master/LICENSE
