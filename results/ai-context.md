# Honeypot Intelligence Report — AI Context Document

Generated: 2026-05-28 17:01 UTC
Dataset: 11,611,908 Wazuh alerts from 6-day honeypot capture

---

## Summary Statistics

- Total events: 11,611,908
- Unique attacker IPs: 1,321
- Countries: 105
- Successful honeypot logins: 5,358
- Failed login attempts: 873,373
- Commands executed in fake shell: 501,689
- File downloads attempted: 165,580
- File uploads attempted: 5,656
- Unique credential pairs: 4,072
- Unique HASSH fingerprints: 51
- Average session duration: 23.2s
- Longest session: 310.1s

## Event Type Breakdown

- cowrie.session.closed: 2,623,702
- cowrie.session.connect: 2,622,641
- cowrie.client.version: 1,340,503
- cowrie.client.kex: 1,337,064
- cowrie.login.failed: 873,373
- : 515,208
- cowrie.command.input: 501,689
- cowrie.log.closed: 490,629
- cowrie.session.params: 490,612
- cowrie.login.success: 461,930
- cowrie.session.file_download: 165,580
- cowrie.command.failed: 164,567
- cowrie.telnet.option: 7,864
- cowrie.session.file_upload: 5,656
- cowrie.client.fingerprint: 2,702
- cowrie.direct-tcpip.request: 2,597
- cowrie.direct-tcpip.data: 2,595
- cowrie.direct-tcpip.ja4h: 2,339
- cowrie.client.size: 258
- cowrie.direct-tcpip.ja4: 203
- cowrie.client.var: 77
- cowrie.telnet.exploit_attempt: 76
- cowrie.session.file_download.failed: 43

## Top 25 Attacker Countries

1. The Netherlands: 1,579,555 events (14.2%)
2. Indonesia: 1,308,487 events (11.8%)
3. Germany: 1,308,410 events (11.8%)
4. United States: 1,231,291 events (11.1%)
5. Bulgaria: 723,627 events (6.5%)
6. Hong Kong: 563,613 events (5.1%)
7. Canada: 417,574 events (3.8%)
8. Singapore: 323,633 events (2.9%)
9. India: 306,532 events (2.8%)
10. South Korea: 291,989 events (2.6%)
11. Vietnam: 257,708 events (2.3%)
12. Brazil: 233,726 events (2.1%)
13. France: 213,529 events (1.9%)
14. Argentina: 169,876 events (1.5%)
15. Romania: 140,835 events (1.3%)
16. Taiwan: 127,864 events (1.2%)
17. Mexico: 115,841 events (1.0%)
18. Belgium: 102,799 events (0.9%)
19. Kazakhstan: 81,902 events (0.7%)
20. Kenya: 74,033 events (0.7%)
21. United Kingdom: 72,774 events (0.7%)
22. Russia: 67,659 events (0.6%)
23. Sweden: 67,601 events (0.6%)
24. Nigeria: 58,413 events (0.5%)
25. Colombia: 56,252 events (0.5%)

## Top 20 Attacker ASNs (Infrastructure)

1. AS51396: 2,823,139 events
2. AS138136: 1,078,494 events
3. AS14061: 980,680 events
4. AS132203: 322,960 events
5. AS8075: 281,664 events
6. AS135377: 281,387 events
7. AS396982: 177,063 events
8. AS16276: 161,897 events
9. AS4766: 141,805 events
10. AS47890: 140,131 events
11. AS45102: 126,015 events
12. AS48090: 124,362 events
13. AS3449: 123,675 events
14. AS135383: 84,131 events
15. AS138608: 77,359 events
16. AS31898: 72,707 events
17. AS37061: 69,207 events
18. AS215540: 66,901 events
19. AS4780: 62,922 events
20. AS29465: 57,938 events

## Top 25 Attempted Passwords

1. `3245gs5662d34`: 161,992 attempts
2. `345gs5662d34`: 161,584 attempts
3. `123456`: 81,652 attempts
4. `123`: 30,060 attempts
5. `1234`: 22,809 attempts
6. `1`: 16,957 attempts
7. `password`: 15,754 attempts
8. `12345678`: 15,448 attempts
9. `admin`: 14,169 attempts
10. `12345`: 11,888 attempts
11. `root`: 11,667 attempts
12. `123456789`: 7,719 attempts
13. `abc123`: 6,787 attempts
14. `1qaz@WSX`: 5,347 attempts
15. `admin123`: 4,629 attempts
16. `123123`: 4,552 attempts
17. `111111`: 4,421 attempts
18. `test`: 4,404 attempts
19. `qwerty`: 4,123 attempts
20. `toor`: 4,083 attempts
21. `user`: 4,082 attempts
22. `ubuntu`: 3,646 attempts
23. `Aa123456`: 3,288 attempts
24. `P@ssw0rd`: 3,200 attempts
25. `123321`: 2,887 attempts

## Top 25 Attempted Usernames

1. `root`: 466,811 attempts
2. `345gs5662d34`: 161,584 attempts
3. `admin`: 37,864 attempts
4. `user`: 29,589 attempts
5. `ubuntu`: 28,390 attempts
6. `test`: 14,376 attempts
7. `deploy`: 13,623 attempts
8. `postgres`: 9,956 attempts
9. `sol`: 8,755 attempts
10. `user1`: 7,770 attempts
11. `ftpuser`: 6,912 attempts
12. `minecraft`: 6,571 attempts
13. `dev`: 6,345 attempts
14. `steam`: 6,181 attempts
15. `oracle`: 5,982 attempts
16. `pi`: 5,933 attempts
17. `mysql`: 5,545 attempts
18. `guest`: 5,305 attempts
19. `debian`: 5,094 attempts
20. `frappe`: 5,070 attempts
21. `git`: 4,928 attempts
22. `solana`: 4,819 attempts
23. `testuser`: 4,798 attempts
24. `claude`: 4,241 attempts
25. `server`: 4,164 attempts

## Top 25 Credential Pairs

1. `root` / `3245gs5662d34`: 161,992 attempts
2. `345gs5662d34` / `345gs5662d34`: 161,584 attempts
3. `admin` / `admin`: 6,747 attempts
4. `root` / `admin`: 3,655 attempts
5. `root` / `root`: 2,936 attempts
6. `ubuntu` / `ubuntu`: 2,558 attempts
7. `GET / HTTP/1.1` / `Host: 174.138.35.11:23`: 2,363 attempts
8. `solana` / `solana`: 2,099 attempts
9. `user` / `user`: 2,032 attempts
10. `admin` / `admin123`: 1,786 attempts
11. `root` / `root123`: 1,727 attempts
12. `admin` / `1234`: 1,583 attempts
13. `sol` / `123`: 1,573 attempts
14. `node` / `node`: 1,556 attempts
15. `sol` / `sol`: 1,542 attempts
16. `user` / `password`: 1,514 attempts
17. `root` / `toor`: 1,449 attempts
18. `root` / `123456`: 1,447 attempts
19. `root` / `password`: 1,446 attempts
20. `postgres` / `123`: 1,378 attempts
21. `root` / `1qaz@WSX`: 1,329 attempts
22. `User-Agent` / ` Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36:Accept-Encoding: gzip`: 1,293 attempts
23. `*1` / `$4`: 1,284 attempts
24. `ubuntu` / `123456`: 1,274 attempts
25. `root` / `1`: 1,260 attempts

## Top 25 Commands Executed

1. (149,509x) `cd ~; chattr -ia .ssh; lockr -ia .ssh`
2. (149,348x) `cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7Vv...`
3. (113,080x) `uname -s -v -n -r -m`
4. (2,497x) `echo SHELL_TEST`
5. (2,073x) `uname -a`
6. (2,034x) `whoami`
7. (1,945x) `uname -m`
8. (1,901x) `cat /proc/cpuinfo \| grep name \| wc -l`
9. (1,821x) `rm -rf /tmp/secure.sh; rm -rf /tmp/auth.sh; pkill -9 secure.sh; pkill -9 auth.sh; echo > /etc/hosts....`
10. (1,819x) `cat /proc/cpuinfo \| grep name \| head -n 1 \| awk '{print $4,$5,$6,$7,$8,$9;}'`
11. (1,813x) `free -m \| grep Mem \| awk '{print $2 ,$3, $4, $5, $6, $7}'`
12. (1,810x) `ls -lh $(which ls)`
13. (1,807x) `which ls`
14. (1,807x) `cat /proc/cpuinfo \| grep model \| grep name \| wc -l`
15. (1,806x) `w`
16. (1,806x) `df -h \| head -n 2 \| awk 'FNR == 2 {print $2;}'`
17. (1,805x) `crontab -l`
18. (1,805x) `top`
19. (1,804x) `lscpu \| grep Model`
20. (1,803x) `uname`
21. (1,724x) `export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH; uname=$(uname -s -v ...`
22. (1,721x) `cat /proc/uptime 2 > /dev/null \| cut -d. -f1`
23. (1,721x) `uname -m 2 > /dev/null`
24. (1,720x) `uname -s -v -n -m 2 > /dev/null`
25. (1,244x) `/bin/./uname -s -v -n -r -m`

## SSH Tool Fingerprints (HASSH)

1. Paramiko 2.x (Python SSH library) — `f555226df1963d1d3c09daf865abdc9a`: 640,253 sessions
2. Go SSH scanner — `0a07365cc01fa9fc82608ba4019af499`: 545,398 sessions
3. OpenSSH 9.0-9.7 (post-quantum mlkem) — `16443846184eafde36765c9bab2f4397`: 46,789 sessions
4. AsyncSSH (Python async SSH framework) — `03a80b21afa810682a776a7d42e5e6fb`: 30,769 sessions
5. OpenSSH 9.9+ (mlkem768nistp256 + sntrup761) — `af8223ac9914f509afdadfaf5f7ee94e`: 15,337 sessions
6. OpenSSH 8.x — `e54ef3ec27fe1fea7ab64d3fa05359fd`: 11,468 sessions
7. Unknown tool — `2ec37a7cc8daf20b10e1ad6221061ca5`: 10,695 sessions
8. Unknown tool — `bf7dbf67fa9b26ee9f9deb99c49320ba`: 3,728 sessions
9. Unknown tool — `57446c12547a668110aa237e5965e374`: 3,345 sessions
10. Unknown tool — `fda360b1b4f4d3455cb75c6e7edb1d11`: 2,934 sessions
11. Legacy SSH library (pre-2015) — `b21d7cdcc8133dc2b430d1a039fece20`: 2,699 sessions
12. OpenSSH 8.x — `5bd26477da5440a6187bd3f1b39a429c`: 2,549 sessions
13. OpenSSH 8.x — `19532158b559096b89b1a5f7d17175b2`: 2,342 sessions
14. Unknown tool — `084386fa7ae5039bcf6f07298a05a227`: 1,999 sessions
15. Unknown tool — `e788c657d1a22971d5026526ffd2e918`: 1,812 sessions
16. OpenSSH 8.x — `4e066189c3bbeec38c99b1855113733a`: 1,321 sessions
17. Unknown tool — `dd9bcf093c355da7000132131cb36fd0`: 1,278 sessions
18. OpenSSH 7.x (older) — `bc9e7273cde22b1209d6673b5fd10bd5`: 1,238 sessions
19. Unknown tool — `f1e5e9d24e5e345e8745613bde22d532`: 1,096 sessions
20. Unknown tool — `aae6b9604f6f3356543709a376d7f657`: 976 sessions

## File Downloads Attempted (Malware Delivery)

1. (149,364x) `var/lib/cowrie/downloads/a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2`
2. (1,826x) `var/lib/cowrie/downloads/01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b`
3. (43x) `var/lib/cowrie/downloads/e7d3456c307053b17b8ad52d390634d129a4d1165439ffa412f26d173b29d565`
4. (10x) `var/lib/cowrie/downloads/6b3a55e0261b0304143f805a24924d0c1c44524821305f31d9277843b8a10f4e`

## Daily Event Volume

- 2026-05-23: 349,705 events
- 2026-05-24: 2,350,405 events
- 2026-05-25: 2,688,520 events
- 2026-05-26: 1,742,714 events
- 2026-05-27: 2,675,054 events
- 2026-05-28: 1,805,510 events

## Wazuh Alert Severity Distribution

- CRITICAL (Level 12): 14,377 alerts
- HIGH (Level 10): 561,960 alerts
- MEDIUM-HIGH (Level 8): 487,328 alerts
- Level 7 (Level 7): 253 alerts
- MEDIUM (Level 6): 809,585 alerts
- Level 5 (Level 5): 471,934 alerts
- Level 4 (Level 4): 20 alerts
- LOW (Level 3): 9,266,451 alerts

