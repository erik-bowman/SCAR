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

sub VULN_ID {
    my ($self) = @_;
    $self->{VULN_ID} = 'V-38684';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'low';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000027';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50485r2_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000319';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The system must limit users to 10 simultaneous system logins, or a site-defined number, in accordance with operational requirements.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Limiting simultaneous user logins can insulate the system from denial of service problems caused by excessive logins. Automated login processes operating improperly or maliciously may result in an exceptional number of simultaneous login sessions.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Run the following command to ensure the ""maxlogins"" value is configured for all users on the system:



$ grep ""maxlogins"" /etc/security/limits.conf /etc/security/limits.d/*.conf



You should receive output similar to the following:



* hard maxlogins 10



If it is not similar, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Limiting the number of allowed users and sessions per user can limit risks related to denial of service attacks. This addresses concurrent sessions for a single account and does not address concurrent sessions by a single user via multiple accounts. To set the number of concurrent sessions per user add the following line in ""/etc/security/limits.conf"":



* hard maxlogins 10



A documented site-defined number may be substituted for 10 in the above.
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000054

The information system limits the number of concurrent sessions for each organization-defined account and/or account type to an organization-defined number of sessions.

NIST SP 800-53 :: AC-10

NIST SP 800-53A :: AC-10.1 (ii)

NIST SP 800-53 Revision 4 :: AC-10




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
