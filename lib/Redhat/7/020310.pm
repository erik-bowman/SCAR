# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::020310
#
# VULN ID
#   V-72005
#
# SEVERITY
#   high
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86629r1_rule
#
# STIG ID
#   RHEL-07-020310
#
# RULE TITLE
#   The root account must be the only account having unrestricted access to the system.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::020310;

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
    return 'V-72005';
}

sub get_severity {
    return 'high';
}

sub get_group_title {
    return 'SRG-OS-000480-GPOS-00227';
}

sub get_rule_id {
    return 'SV-86629r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-020310';
}

sub get_rule_title {
    return
        'The root account must be the only account having unrestricted access to the system.';
}

sub get_discussion {
    return <<'DISCUSSION';
If an account other than root also has a User Identifier (UID) of ""0"", it has root authority, giving that account unrestricted access to the entire operating system. Multiple accounts with a UID of ""0"" afford an opportunity for potential intruders to guess a password for a privileged account.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Check the system for duplicate UID ""0"" assignments with the following command:



# awk -F: '$3 == 0 {print $1}' /etc/passwd



If any accounts other than root have a UID of ""0"", this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Change the UID of any account on the system, other than root, that has a UID of ""0"".



If the account is associated with system commands or applications, the UID should be changed to one greater than ""0"" but less than ""1000"". Otherwise, assign a UID of greater than ""1000"" that has not already been assigned.
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
