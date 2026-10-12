# Evaluation - holdout

Model: `llama3.1:8b` | 29 samples (18 attack / 11 benign) | 10 within the rules' scope

## Summary

| configuration | verdict | severity | technique | fields | precision | recall | FP | mean latency |
|---|---|---|---|---|---|---|---|---|
| rules | 17/29 | 15/29 | 16/29 | **48/87** | 1.00 | 0.33 | 0 | <1ms |
| analyze_v2 | 22/29 | 21/29 | 19/29 | **62/87** | 0.93 | 0.78 | 1 | 14796ms |
| analyze_v3 | 21/29 | 18/29 | 18/29 | **57/87** | 0.87 | 0.72 | 2 | 15061ms |
| analyze_v3+rules | 22/29 | 19/29 | 19/29 | **60/87** | 0.88 | 0.78 | 2 | 15061ms |

Precision and recall are over attack-vs-benign, which is the decision an
analyst acts on. FP counts benign samples reported as an attack.


## rules

| sample | in scope | verdict | severity | technique | v | s | m |
|---|---|---|---|---|---|---|---|
| imap_brute_success.log | yes | malicious | critical | T1110 | ok | ok | ok |
| sudo_wget_shell.log | yes | malicious | critical | T1059.004 | ok | ok | ok |
| adduser_root_group.log | yes | malicious | critical | T1136.001 | ok | ok | ok |
| shadow_copy_exfil.log | yes | malicious | high | T1003.008 | ok | X | ok |
| audit_log_wipe.log | yes | malicious | high | T1070.002 | ok | ok | ok |
| nginx_sqli.log | no | benign | info | - | X | X | X |
| webshell_upload.log | no | benign | info | - | X | X | X |
| path_traversal.log | no | benign | info | - | X | X | X |
| reverse_shell.log | no | malicious | high | T1548.003 | ok | X | X |
| cron_persistence.log | no | benign | info | - | X | X | X |
| authorized_keys_backdoor.log | no | benign | info | - | X | X | X |
| defenses_disabled.log | no | benign | info | - | X | X | X |
| windows_failed_logons.log | no | benign | info | - | X | X | X |
| cloudtrail_iam_abuse.log | no | benign | info | - | X | X | X |
| port_scan.log | no | benign | info | - | X | X | X |
| dns_tunnel.log | no | benign | info | - | X | X | X |
| cryptominer.log | no | benign | info | - | X | X | X |
| docker_socket_escape.log | no | benign | info | - | X | X | X |
| benign_logrotate.log | yes | benign | info | - | ok | ok | ok |
| benign_devops_curl.log | yes | benign | info | - | ok | ok | ok |
| benign_failed_su.log | yes | benign | info | - | ok | ok | ok |
| benign_service_account.log | yes | benign | info | - | ok | ok | ok |
| benign_new_employee.log | yes | benign | info | - | ok | ok | ok |
| benign_patching.log | no | benign | info | - | ok | ok | ok |
| benign_backup.log | no | benign | info | - | ok | ok | ok |
| benign_certbot.log | no | benign | info | - | ok | ok | ok |
| benign_monitoring.log | no | benign | info | - | ok | ok | ok |
| benign_crawler_404s.log | no | benign | info | - | ok | ok | ok |
| benign_docker_deploy.log | no | benign | info | - | ok | ok | ok |

## analyze_v2

| sample | in scope | verdict | severity | technique | v | s | m |
|---|---|---|---|---|---|---|---|
| imap_brute_success.log | yes | suspicious | medium | T1110 | X | X | ok |
| sudo_wget_shell.log | yes | malicious | critical | T1059.004 | ok | ok | ok |
| adduser_root_group.log | yes | malicious | critical | T1136.003 | ok | ok | X |
| shadow_copy_exfil.log | yes | malicious | critical | T1059.004 | ok | ok | X |
| audit_log_wipe.log | yes | malicious | critical | T1059.004 | ok | X | X |
| nginx_sqli.log | no | malicious | high | T1190 | ok | ok | ok |
| webshell_upload.log | no | malicious | critical | T1059.004 | ok | ok | ok |
| path_traversal.log | no | malicious | high | T1041 | X | X | X |
| reverse_shell.log | no | malicious | critical | T1059.004 | ok | ok | ok |
| cron_persistence.log | no | benign | info | - | X | X | X |
| authorized_keys_backdoor.log | no | malicious | high | T1098.004 | ok | ok | ok |
| defenses_disabled.log | no | malicious | high | T1562.001 | ok | ok | ok |
| windows_failed_logons.log | no | malicious | critical | T1110 | ok | ok | ok |
| cloudtrail_iam_abuse.log | no | malicious | critical | T1110 | ok | ok | X |
| port_scan.log | no | benign | info | - | X | X | X |
| dns_tunnel.log | no | malicious | high | T1572 | ok | ok | ok |
| cryptominer.log | no | benign | info | - | X | X | X |
| docker_socket_escape.log | no | benign | info | - | X | X | X |
| benign_logrotate.log | yes | benign | info | - | ok | ok | ok |
| benign_devops_curl.log | yes | benign | info | - | ok | ok | ok |
| benign_failed_su.log | yes | suspicious | medium | T1098 | X | X | X |
| benign_service_account.log | yes | benign | info | - | ok | ok | ok |
| benign_new_employee.log | yes | benign | info | - | ok | ok | ok |
| benign_patching.log | no | benign | info | - | ok | ok | ok |
| benign_backup.log | no | benign | info | - | ok | ok | ok |
| benign_certbot.log | no | benign | info | - | ok | ok | ok |
| benign_monitoring.log | no | benign | info | - | ok | ok | ok |
| benign_crawler_404s.log | no | benign | info | - | ok | ok | ok |
| benign_docker_deploy.log | no | benign | info | - | ok | ok | ok |

## analyze_v3

| sample | in scope | verdict | severity | technique | v | s | m |
|---|---|---|---|---|---|---|---|
| imap_brute_success.log | yes | benign | info | - | X | X | X |
| sudo_wget_shell.log | yes | malicious | critical | T1059.004 | ok | ok | ok |
| adduser_root_group.log | yes | malicious | critical | T1136.003 | ok | ok | X |
| shadow_copy_exfil.log | yes | malicious | critical | T1059.004 | ok | ok | X |
| audit_log_wipe.log | yes | malicious | critical | T1548.003 | ok | X | X |
| nginx_sqli.log | no | malicious | critical | T1190 | ok | X | ok |
| webshell_upload.log | no | malicious | critical | T1059.004 | ok | ok | ok |
| path_traversal.log | no | malicious | high | T1041 | X | X | X |
| reverse_shell.log | no | malicious | critical | T1059.004 | ok | ok | ok |
| cron_persistence.log | no | benign | info | - | X | X | X |
| authorized_keys_backdoor.log | no | malicious | critical | T1098.004 | ok | X | ok |
| defenses_disabled.log | no | malicious | high | T1562.001 | ok | ok | ok |
| windows_failed_logons.log | no | malicious | critical | T1110 | ok | ok | ok |
| cloudtrail_iam_abuse.log | no | malicious | critical | T1136.003 | ok | ok | ok |
| port_scan.log | no | benign | info | - | X | X | X |
| dns_tunnel.log | no | malicious | high | T1572 | ok | ok | ok |
| cryptominer.log | no | benign | info | - | X | X | X |
| docker_socket_escape.log | no | benign | info | - | X | X | X |
| benign_logrotate.log | yes | benign | info | - | ok | ok | ok |
| benign_devops_curl.log | yes | malicious | critical | T1059.004 | X | X | X |
| benign_failed_su.log | yes | benign | info | - | ok | ok | ok |
| benign_service_account.log | yes | benign | info | - | ok | ok | ok |
| benign_new_employee.log | yes | malicious | critical | T1136.003 | X | X | X |
| benign_patching.log | no | benign | info | - | ok | ok | ok |
| benign_backup.log | no | benign | info | - | ok | ok | ok |
| benign_certbot.log | no | benign | info | - | ok | ok | ok |
| benign_monitoring.log | no | benign | info | - | ok | ok | ok |
| benign_crawler_404s.log | no | benign | info | - | ok | ok | ok |
| benign_docker_deploy.log | no | benign | info | - | ok | ok | ok |

## analyze_v3+rules

| sample | in scope | verdict | severity | technique | v | s | m |
|---|---|---|---|---|---|---|---|
| imap_brute_success.log | yes | malicious | critical | T1110 | ok | ok | ok |
| sudo_wget_shell.log | yes | malicious | critical | T1059.004 | ok | ok | ok |
| adduser_root_group.log | yes | malicious | critical | T1136.003 | ok | ok | X |
| shadow_copy_exfil.log | yes | malicious | critical | T1059.004 | ok | ok | X |
| audit_log_wipe.log | yes | malicious | critical | T1548.003 | ok | X | X |
| nginx_sqli.log | no | malicious | critical | T1190 | ok | X | ok |
| webshell_upload.log | no | malicious | critical | T1059.004 | ok | ok | ok |
| path_traversal.log | no | malicious | high | T1041 | X | X | X |
| reverse_shell.log | no | malicious | critical | T1059.004 | ok | ok | ok |
| cron_persistence.log | no | benign | info | - | X | X | X |
| authorized_keys_backdoor.log | no | malicious | critical | T1098.004 | ok | X | ok |
| defenses_disabled.log | no | malicious | high | T1562.001 | ok | ok | ok |
| windows_failed_logons.log | no | malicious | critical | T1110 | ok | ok | ok |
| cloudtrail_iam_abuse.log | no | malicious | critical | T1136.003 | ok | ok | ok |
| port_scan.log | no | benign | info | - | X | X | X |
| dns_tunnel.log | no | malicious | high | T1572 | ok | ok | ok |
| cryptominer.log | no | benign | info | - | X | X | X |
| docker_socket_escape.log | no | benign | info | - | X | X | X |
| benign_logrotate.log | yes | benign | info | - | ok | ok | ok |
| benign_devops_curl.log | yes | malicious | critical | T1059.004 | X | X | X |
| benign_failed_su.log | yes | benign | info | - | ok | ok | ok |
| benign_service_account.log | yes | benign | info | - | ok | ok | ok |
| benign_new_employee.log | yes | malicious | critical | T1136.003 | X | X | X |
| benign_patching.log | no | benign | info | - | ok | ok | ok |
| benign_backup.log | no | benign | info | - | ok | ok | ok |
| benign_certbot.log | no | benign | info | - | ok | ok | ok |
| benign_monitoring.log | no | benign | info | - | ok | ok | ok |
| benign_crawler_404s.log | no | benign | info | - | ok | ok | ok |
| benign_docker_deploy.log | no | benign | info | - | ok | ok | ok |
