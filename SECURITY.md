# Reporting Security Issues

If you discover a potential security issue in this project, please notify AWS/Amazon Security via
our [vulnerability reporting page](http://aws.amazon.com/security/vulnerability-reporting/), or
email <aws-security@amazon.com> directly.

**Please do not create a public GitHub issue.**

## Please do not paste customer configuration

Issues and pull requests in this repository attract AWS WAF exports. A `get-web-acl` response
contains web ACL ARNs, account IDs, IP set contents, header and cookie names, and URI paths. Redact
those before sharing anything in a public issue, or send the detail through the reporting page
above instead.

## Scope note

This project is sample code that performs an offline configuration review. It calls no AWS API,
makes no network requests, and never modifies an AWS resource — see
[Blast radius](README.md#blast-radius). A finding it reports is a configuration observation, not a
demonstrated exploit, and the assessment is not a penetration test.
