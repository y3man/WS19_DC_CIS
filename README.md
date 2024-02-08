# The script

This script compares settings of Windows server (focus on Domain Controller) with CIS benchmark recommendations.

The script was created using CIS Windows Server 2019 Benchmark v2.0.0.
[CIS](https://www.cisecurity.org/cis-benchmarks/)

## Data sources

- Security settings, user rights assignment and password policies are collected from file exported using `secedit` command. The file is then parsed and settings are compared with CIS benchmark recommendations.
- Audit policies are collected from file exported using the `auditpol` command and compared with CIS benchmark recommendations.
- Other settings are chceked using `Get-ItemPropertyValue` command and compared with CIS benchmark recommendations.

