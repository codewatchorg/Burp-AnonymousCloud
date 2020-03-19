# Burp-AnonymousCloud
Burp extension that performs a passive scan to identify cloud buckets and then test them for publicly accessible vulnerabilities.

The extension looks at all responses and will note:
1. AWS S3 bucket URLs.
2. Azure Storage container URLs.
3. Google Storage container URLs.

The extension checks the following things as an anonymous user:
1. Publicly accessible S3 buckets which will be enumerated by the extension.
2. Publicly accessible ACLs on S3 buckets which will be enumerated by the extension.
3. Publicly writable S3 buckets, to which a sample file will be written.
4. Publicly writable ACLs on S3 buckets.
5. Publicly accessible Google Storage containers which will be enumerated by the extension.
6. Publicly accessible ACLs on Google Storage containers which will be enumerated by the extension.
7. Publicly writable Google Storage containers, to which a sample file will be written.
8. Publicly accessible Azure Storage containers which will be enumerated by the extension.
9. Publicly accessible Firebase DBs and anonymous read/write access.

The extension checks the following things in AWS/Google as an authenticated AWS/Google user (though not a defined user for the bucket itself):
1. Any authenticated AWS user accessible S3 buckets which will be enumerated by the extension.
2. Any authenticated AWS user accessible ACLs on S3 buckets which will be enumerated by the extension.
3. Any authenticated AWS user writable S3 buckets, to which a sample file will be written.
4. Any authenticated AWS user writable ACLs on S3 buckets.
5. Any authenticated Google user accessible Google Storage containers which will be enumerated by the extension.
6. Any authenticated Google user accessible ACLs on Google Storage containers which will be enumerated by the extension.
7. Any authenticated Google user writable Google Storage containers, to which a sample file will be written.

The extension performs subdomain takeover testing for the following resoures:
1. CNAMEs pointing to non-existent AWS S3 buckets.
2. CNAMEs pointing to non-existent Azure resources.
3. CNAMEs pointing to non-existent Heroku services.
4. CNAMEs pointing to non-existent Github pages.

Subdomains are collected from the following:
1. HackerTarget
2. BufferOver
3. Wayback Machine
4. Crt.sh
5. File list
6. Shodan (with an API key)
7. Censys (with an API key)

Usage
=====

All you have to do is add the JAR as an extension in Burp, add the appropriate targets to scope, and run a scan against the targets. If you want to test for permissions issues that allow all authenticated AWS users, then add your personal AWS credentials.


Future
======

Continue adding features to support identification and enumeration of other resources such Azure database.
