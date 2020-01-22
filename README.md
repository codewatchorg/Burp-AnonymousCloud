# Burp-AnonymousCloud
Burp extension that performs a passive scan to identify cloud buckets and then test them for publicly accessible vulnerabilities

The extension looks at all responses and will note:
1. AWS S3 bucket URLs.
2. Azure Storage container URLs.
3. Google Storage container URLs.

The extension checks the following things in AWS as an anonymous user:
1. Publicly accessible S3 buckets which will be enumerated by the extension.
2. Publicly accessible ACLs on S3 buckets which will be enumerated by the extension.
3. Publicly writable S3 buckets, to which a sample file will be written.
4. Publicly writable ACLs on S3 buckets.

The extension checks the following things in AWS as an authenticated AWS user (though not a defined user for the bucket itself):
1. Any authenticated AWS user accessible S3 buckets which will be enumerated by the extension.
2. Any authenticated AWS user accessible ACLs on S3 buckets which will be enumerated by the extension.
3. Any authenticated AWS user writable S3 buckets, to which a sample file will be written.
4. Any authenticated AWS user writable ACLs on S3 buckets.

Usage
=====

All you have to do is add the JAR as an extension in Burp, add the appropriate targets to scope, and run a scan against the targets. If you want to test for permissions issues that allow all authenticated AWS users, then add your personal AWS credentials.


Future
======

Add features that identify vulnerabilities in Azure/Google that are similar to the issues it identifies in AWS.
