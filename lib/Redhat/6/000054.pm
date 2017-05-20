# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000054
#
# VULN ID
#   V-38480
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-999999
#
# RULE ID
#   SV-50280r1_rule
#
# STIG ID
#   RHEL-06-000054
#
# RULE TITLE
#   Users must be warned 7 days in advance of password expiration.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000054;

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
    return 'V-38480';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-999999';
}

sub get_rule_id {
    return 'SV-50280r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000054';
}

sub get_rule_title {
    return 'Users must be warned 7 days in advance of password expiration.';
}

sub get_discussion {
    return <<'DISCUSSION';
Setting the password warning age enables users to make the change at a practical time.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To check the password warning age, run the command:



$ grep PASS_WARN_AGE /etc/login.defs



The DoD requirement is 7.

If it is not set to the required value, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
To specify how many days prior to password expiration that a warning will be issued to users, edit the file ""/etc/login.defs"" and add or correct the following line, replacing [DAYS] appropriately:



PASS_WARN_AGE [DAYS]



The DoD requirement is 7.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000366

The organization implements the security configuration settings.

NIST SP 800-53 :: CM-6 b

NIST SP 800-53A :: CM-6.1 (iv)

NIST SP 800-53 Revision 4 :: CM-6 b




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
