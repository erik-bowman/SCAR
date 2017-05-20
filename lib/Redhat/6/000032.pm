# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000032
#
# VULN ID
#   V-38500
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-999999
#
# RULE ID
#   SV-50301r2_rule
#
# STIG ID
#   RHEL-06-000032
#
# RULE TITLE
#   The root account must be the only account having a UID of 0.
#
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000032;

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
    foreach my $passwd_entry ( keys %{ $self->{parent}->{passwd} } ) {
        if ( $self->{parent}->{passwd}->{$passwd_entry}->{name} ne 'root' ) {
            if ( $self->{parent}->{passwd}->{$passwd_entry}->{uid} eq '0' ) {
                $self->_set_finding_status('O');
            }
        }
    }
    if ( !defined $self->get_finding_status() ) {
        $self->_set_finding_status('NF');
    }
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
    return 'V-38500';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-999999';
}

sub get_rule_id {
    return 'SV-50301r2_rule';
}

sub get_stig_id {
    return 'RHEL-06-000032';
}

sub get_rule_title {
    return 'The root account must be the only account having a UID of 0.';
}

sub get_discussion {
    return <<'DISCUSSION';
An account has root authority if it has a UID of 0. Multiple accounts with a UID of 0 afford more opportunity for potential intruders to guess a password for a privileged account. Proper configuration of sudo is recommended to afford multiple system administrators access to root privileges in an accountable manner.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To list all password file entries for accounts with UID 0, run the following command:



# awk -F: '($3 == 0) {print}' /etc/passwd



This should print only one line, for the user root.

If any account other than root has a UID of 0, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
If any account other than root has a UID of 0, this misconfiguration should be investigated and the accounts other than root should be removed or have their UID changed.
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
