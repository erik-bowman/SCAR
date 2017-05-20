# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000071
#
# VULN ID
#   V-38590
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000030
#
# RULE ID
#   SV-50391r1_rule
#
# STIG ID
#   RHEL-06-000071
#
# RULE TITLE
#   The system must allow locking of the console screen in text mode.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000071;

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
    return 'V-38590';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-000030';
}

sub get_rule_id {
    return 'SV-50391r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000071';
}

sub get_rule_title {
    return
        'The system must allow locking of the console screen in text mode.';
}

sub get_discussion {
    return <<'DISCUSSION';
Installing ""screen"" ensures a console locking capability is available for users who may need to suspend console logins.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Run the following command to determine if the ""screen"" package is installed:



# rpm -q screen





If the package is not installed, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
To enable console screen locking when in text mode, install the ""screen"" package:



# yum install screen



Instruct users to begin new terminal sessions with the following command:



$ screen



The console can now be locked with the following key combination:



ctrl+a x
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000058

The information system provides the capability for users to directly initiate session lock mechanisms.

NIST SP 800-53 :: AC-11 a

NIST SP 800-53A :: AC-11

NIST SP 800-53 Revision 4 :: AC-11 a




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
