# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000319
#
# VULN ID
#   V-38684
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000027
#
# RULE ID
#   SV-50485r2_rule
#
# STIG ID
#   RHEL-06-000319
#
# RULE TITLE
#   The system must limit users to 10 simultaneous system logins, or a site-defined number, in accordance with operational requirements.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000319;

# Standard modules
use utf8;
use strict;
use warnings FATAL => 'all';

# Scar modules
use Scar;
use Scar::Util::Log;
use Scar::Util::Backup;

# Plugin version
our $VERSION = 0.01;

sub new {
    my ( $class, $parent ) = @_;
    my $self = bless { parent => $parent }, $class;

    return $self;
}

sub check {
    my ($self) = @_;

    return $self;
}

sub remediate {
    my ($self) = @_;

    return $self;
}

sub _set_finding_status {
    my ( $self, $finding_status ) = @_;
    $self->{finding_status} = $finding_status;
    return $self->{finding_status};
}

sub get_finding_status {
    my ($self) = @_;
    return defined $self->{finding_status} ? $self->{finding_status} : undef;
}

sub get_vuln_id {
    return 'V-38684';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-000027';
}

sub get_rule_id {
    return 'SV-50485r2_rule';
}

sub get_stig_id {
    return 'RHEL-06-000319';
}

sub get_rule_title {
    return
        'The system must limit users to 10 simultaneous system logins, or a site-defined number, in accordance with operational requirements.';
}

sub get_discussion {
    return <<'DISCUSSION';
Limiting simultaneous user logins can insulate the system from denial of service problems caused by excessive logins. Automated login processes operating improperly or maliciously may result in an exceptional number of simultaneous login sessions.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Run the following command to ensure the ""maxlogins"" value is configured for all users on the system:



$ grep ""maxlogins"" /etc/security/limits.conf /etc/security/limits.d/*.conf



You should receive output similar to the following:



* hard maxlogins 10



If it is not similar, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Limiting the number of allowed users and sessions per user can limit risks related to denial of service attacks. This addresses concurrent sessions for a single account and does not address concurrent sessions by a single user via multiple accounts. To set the number of concurrent sessions per user add the following line in ""/etc/security/limits.conf"":



* hard maxlogins 10



A documented site-defined number may be substituted for 10 in the above.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000054

The information system limits the number of concurrent sessions for each organization-defined account and/or account type to an organization-defined number of sessions.

NIST SP 800-53 :: AC-10

NIST SP 800-53A :: AC-10.1 (ii)

NIST SP 800-53 Revision 4 :: AC-10




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
