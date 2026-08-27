





redef digest_salt = "Please change this value.";


@load misc/loaded-scripts


@load misc/capture-loss


@load misc/stats















@load frameworks/software/vulnerable


@load frameworks/software/version-changes


@load-sigs frameworks/signatures/detect-windows-shells


@load protocols/ftp/software
@load protocols/smtp/software
@load protocols/ssh/software
@load protocols/http/software







@load protocols/dns/detect-external-names


@load protocols/ftp/detect


@load protocols/conn/known-hosts
@load protocols/conn/known-services
@load protocols/ssl/known-certs


@load protocols/ssl/validate-certs


@load protocols/ssl/log-hostcerts-only



@load protocols/ssh/geo-data

@load protocols/ssh/detect-bruteforcing

@load protocols/ssh/interesting-hostnames


@load protocols/http/detect-sql-injection




@load frameworks/files/hash-all-files


@load frameworks/files/detect-MHR


@load policy/frameworks/notice/extend-email/hostnames
