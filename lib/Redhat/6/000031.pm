# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000031
#
# VULN ID
#   V-38499
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-999999
#
# RULE ID
#   SV-50300r1_rule
#
# STIG ID
#   RHEL-06-000031
#
# RULE TITLE
#   The /etc/passwd file must not contain password hashes.
#
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000031;

# Standard pragmas
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
    foreach my $passwd_entry ( keys %{ $self->{parent}->{users} } ) {
        if ( $self->{parent}->{users}->{$passwd_entry}->{etc_passwd} ne 'x' )
        {
            $self->_set_finding_status('O');
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
    return 'V-38499';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-999999';
}

sub get_rule_id {
    return 'SV-50300r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000031';
}

sub get_rule_title {
    return 'The /etc/passwd file must not contain password hashes.';
}

sub get_discussion {
    return <<'DISCUSSION';
The hashes for all user account passwords should be stored in the file ""/etc/shadow"" and never in ""/etc/passwd"", which is readable by all users.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To check that no password hashes are stored in ""/etc/passwd"", run the following command:



# awk -F: '($2 != ""x"") {print}' /etc/passwd



If it produces any output, then a password hash is stored in ""/etc/passwd"".

If any stored hashes are found in /etc/passwd, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
If any password hashes are stored in ""/etc/passwd"" (in the second field, instead of an ""x""), the cause of this misconfiguration should be investigated. The account should have its password reset and the hash should be properly stored, or the account should be deleted entirely.
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
