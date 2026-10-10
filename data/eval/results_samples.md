# Evaluation - samples

Model: `llama3.1:8b` | 6 samples (4 attack / 2 benign) | 6 within the rules' scope

## Summary

| configuration | verdict | severity | technique | fields | precision | recall | FP | mean latency |
|---|---|---|---|---|---|---|---|---|
| rules | 6/6 | 6/6 | 6/6 | **18/18** | 1.00 | 1.00 | 0 | <1ms |
| analyze_v1 | 3/6 | 3/6 | 3/6 | **9/18** | 1.00 | 1.00 | 0 | 19358ms |
| analyze_v2 | 5/6 | 5/6 | 5/6 | **15/18** | 0.80 | 1.00 | 1 | 20189ms |
| analyze_v2+rules | 5/6 | 5/6 | 5/6 | **15/18** | 0.80 | 1.00 | 1 | 20189ms |

Precision and recall are over attack-vs-benign, which is the decision an
analyst acts on. FP counts benign samples reported as an attack.


## rules

| sample | in scope | verdict | severity | technique | v | s | m |
|---|---|---|---|---|---|---|---|
| auth_brute_force.log | yes | malicious | critical | T1110 | ok | ok | ok |
| benign_noise.log | yes | benign | info | - | ok | ok | ok |
| privilege_escalation.log | yes | malicious | critical | T1059.004 | ok | ok | ok |
| log_tampering.log | yes | malicious | high | T1070.002 | ok | ok | ok |
| password_spray.log | yes | suspicious | medium | T1110 | ok | ok | ok |
| user_typo.log | yes | benign | info | - | ok | ok | ok |

## analyze_v1

| sample | in scope | verdict | severity | technique | v | s | m |
|---|---|---|---|---|---|---|---|
| auth_brute_force.log | yes | suspicious | medium | T1210 | X | X | X |
| benign_noise.log | yes | benign | info | - | ok | ok | ok |
| privilege_escalation.log | yes | suspicious | medium | T1210 | X | X | X |
| log_tampering.log | yes | suspicious | medium | - | X | X | X |
| password_spray.log | yes | suspicious | medium | T1110 | ok | ok | ok |
| user_typo.log | yes | benign | info | - | ok | ok | ok |

## analyze_v2

| sample | in scope | verdict | severity | technique | v | s | m |
|---|---|---|---|---|---|---|---|
| auth_brute_force.log | yes | malicious | critical | T1110 | ok | ok | ok |
| benign_noise.log | yes | benign | info | - | ok | ok | ok |
| privilege_escalation.log | yes | malicious | critical | T1059.004 | ok | ok | ok |
| log_tampering.log | yes | malicious | high | T1070.002 | ok | ok | ok |
| password_spray.log | yes | suspicious | medium | T1110.003 | ok | ok | ok |
| user_typo.log | yes | malicious | critical | T1110 | X | X | X |

## analyze_v2+rules

| sample | in scope | verdict | severity | technique | v | s | m |
|---|---|---|---|---|---|---|---|
| auth_brute_force.log | yes | malicious | critical | T1110 | ok | ok | ok |
| benign_noise.log | yes | benign | info | - | ok | ok | ok |
| privilege_escalation.log | yes | malicious | critical | T1059.004 | ok | ok | ok |
| log_tampering.log | yes | malicious | high | T1070.002 | ok | ok | ok |
| password_spray.log | yes | suspicious | medium | T1110.003 | ok | ok | ok |
| user_typo.log | yes | malicious | critical | T1110 | X | X | X |
