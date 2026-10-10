# Prompt comparison

Model: `llama3.1:8b`

## Expected

| sample | verdict | severity | acceptable technique |
|---|---|---|---|
| auth_brute_force.log | malicious | critical | T1110, T1110.001, T1110.003, T1078 |
| benign_noise.log | benign | info | (none) |
| privilege_escalation.log | malicious | critical | T1059.004, T1136.001, T1548.003, T1105 |

## analyze_v1

| sample | verdict | severity | technique | v | s | m | latency |
|---|---|---|---|---|---|---|---|
| auth_brute_force.log | suspicious | medium | T1210 | X | X | X | 21024ms |
| benign_noise.log | benign | info | - | ok | ok | ok | 15488ms |
| privilege_escalation.log | suspicious | medium | T1210 | X | X | X | 17833ms |

**analyze_v1: 3/9 fields correct, mean latency 18115ms**

## analyze_v2

| sample | verdict | severity | technique | v | s | m | latency |
|---|---|---|---|---|---|---|---|
| auth_brute_force.log | malicious | critical | T1110 | ok | ok | ok | 21130ms |
| benign_noise.log | benign | info | - | ok | ok | ok | 17308ms |
| privilege_escalation.log | malicious | critical | T1059.004 | ok | ok | ok | 22096ms |

**analyze_v2: 9/9 fields correct, mean latency 20178ms**
