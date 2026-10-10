# Evaluation

Model: `llama3.1:8b` | 6 labelled samples

## Ground truth

| sample | verdict | severity | acceptable technique | why |
|---|---|---|---|---|
| auth_brute_force.log | malicious | critical | T1110, T1110.001, T1110.003, T1078 | Four failed logins then a success from the same IP: the brute force worked. |
| benign_noise.log | benign | info | (none) | Cron sessions, a timer unit and a key-based login from an internal host. |
| privilege_escalation.log | malicious | critical | T1059.004, T1136.001, T1548.003, T1105 | www-data pipes a remote script to root via sudo, then a UID 0 account is created. |
| log_tampering.log | malicious | high | T1070.002 | auth.log truncated, shell history cleared and wtmp removed: anti-forensics. |
| password_spray.log | suspicious | medium | T1110, T1110.003 | Six distinct accounts tried from one external IP, none succeeded. |
| user_typo.log | benign | info | (none) | False-positive trap: two typos then a success from an internal host. Only two failures, below the brute-force threshold. |

## Summary

| configuration | verdict | severity | technique | total | mean latency |
|---|---|---|---|---|---|
| rules | 6/6 | 6/6 | 6/6 | **18/18** | <1ms |
| analyze_v1 | 3/6 | 3/6 | 3/6 | **9/18** | 20142ms |
| analyze_v2 | 5/6 | 5/6 | 5/6 | **15/18** | 20634ms |
| analyze_v2+rules | 5/6 | 5/6 | 5/6 | **15/18** | 20634ms |

## rules

| sample | verdict | severity | technique | v | s | m |
|---|---|---|---|---|---|---|
| auth_brute_force.log | malicious | critical | T1110 | ok | ok | ok |
| benign_noise.log | benign | info | - | ok | ok | ok |
| privilege_escalation.log | malicious | critical | T1059.004 | ok | ok | ok |
| log_tampering.log | malicious | high | T1070.002 | ok | ok | ok |
| password_spray.log | suspicious | medium | T1110 | ok | ok | ok |
| user_typo.log | benign | info | - | ok | ok | ok |

## analyze_v1

| sample | verdict | severity | technique | v | s | m |
|---|---|---|---|---|---|---|
| auth_brute_force.log | suspicious | medium | T1210 | X | X | X |
| benign_noise.log | benign | info | - | ok | ok | ok |
| privilege_escalation.log | suspicious | medium | T1210 | X | X | X |
| log_tampering.log | suspicious | medium | - | X | X | X |
| password_spray.log | suspicious | medium | T1110 | ok | ok | ok |
| user_typo.log | benign | info | - | ok | ok | ok |

## analyze_v2

| sample | verdict | severity | technique | v | s | m |
|---|---|---|---|---|---|---|
| auth_brute_force.log | malicious | critical | T1110 | ok | ok | ok |
| benign_noise.log | benign | info | - | ok | ok | ok |
| privilege_escalation.log | malicious | critical | T1059.004 | ok | ok | ok |
| log_tampering.log | malicious | high | T1070.002 | ok | ok | ok |
| password_spray.log | suspicious | medium | T1110.003 | ok | ok | ok |
| user_typo.log | malicious | critical | T1110 | X | X | X |

## analyze_v2+rules

| sample | verdict | severity | technique | v | s | m |
|---|---|---|---|---|---|---|
| auth_brute_force.log | malicious | critical | T1110 | ok | ok | ok |
| benign_noise.log | benign | info | - | ok | ok | ok |
| privilege_escalation.log | malicious | critical | T1059.004 | ok | ok | ok |
| log_tampering.log | malicious | high | T1070.002 | ok | ok | ok |
| password_spray.log | suspicious | medium | T1110.003 | ok | ok | ok |
| user_typo.log | malicious | critical | T1110 | X | X | X |
