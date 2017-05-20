# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000524
#
# VULN ID
#   V-38439
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000001
#
# RULE ID
#   SV-50239r1_rule
#
# STIG ID
#   RHEL-06-000524
#
# RULE TITLE
#   The system must provide automated support for account management functions.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000524;

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
    return 'V-38439';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000001';
}

sub get_rule_id {
    return 'SV-50239r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000524';
}

sub get_rule_title {
    return
        'The system must provide automated support for account management functions.';
}

sub get_discussion {
    return <<'DISCUSSION';
A comprehensive account management process that includes automation helps to ensure the accounts designated as requiring attention are consistently and promptly addressed. Enterprise environments make user account management challenging and complex. A user management process requiring administrators to manually address account management functions adds risk of potential oversight.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Interview the SA to determine if there is an automated system for managing user accounts, preferably integrated with an existing enterprise user management system.



If there is not, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Implement an automated system for managing user accounts that minimizes the risk of errors, either intentional or deliberate.  If possible, this system should integrate with an existing enterprise user management system, such as, one based Active Directory or Kerberos.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000015

The organization employs automated mechanisms to support the information system account management functions.

NIST SP 800-53 :: AC-2 (1)

NIST SP 800-53A :: AC-2 (1).1

NIST SP 800-53 Revision 4 :: AC-2 (1)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
