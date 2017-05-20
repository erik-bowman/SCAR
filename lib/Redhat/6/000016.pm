# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000016
#
# VULN ID
#   V-38489
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000232
#
# RULE ID
#   SV-50290r1_rule
#
# STIG ID
#   RHEL-06-000016
#
# RULE TITLE
#   A file integrity tool must be installed.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000016;

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
    return 'V-38489';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000232';
}

sub get_rule_id {
    return 'SV-50290r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000016';
}

sub get_rule_title {
    return 'A file integrity tool must be installed.';
}

sub get_discussion {
    return <<'DISCUSSION';
The AIDE package must be installed if it is to be available for integrity checking.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
If another file integrity tool is installed, this is not a finding.



Run the following command to determine if the ""aide"" package is installed:



# rpm -q aide





If the package is not installed, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Install the AIDE package with the command:



# yum install aide
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-001069

The organization employs automated mechanisms to detect the presence of unauthorized software on organizational information systems and notify designated organizational officials in accordance with the organization defined frequency.

NIST SP 800-53 :: RA-5 (7)

NIST SP 800-53A :: RA-5 (7).1 (ii)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__