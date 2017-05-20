# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::020240
#
# VULN ID
#   V-71995
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00228
#
# RULE ID
#   SV-86619r1_rule
#
# STIG ID
#   RHEL-07-020240
#
# RULE TITLE
#   The operating system must define default permissions for all authenticated users in such a way that the user can only read and modify their own files.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::020240;

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
    return 'V-71995';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000480-GPOS-00228';
}

sub get_rule_id {
    return 'SV-86619r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-020240';
}

sub get_rule_title {
    return
        'The operating system must define default permissions for all authenticated users in such a way that the user can only read and modify their own files.';
}

sub get_discussion {
    return <<'DISCUSSION';
Setting the most restrictive default permissions ensures that when new accounts are created, they do not have unnecessary access.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the operating system defines default permissions for all authenticated users in such a way that the user can only read and modify their own files.



Check for the value of the ""UMASK"" parameter in ""/etc/login.defs"" file with the following command:



Note: If the value of the ""UMASK"" parameter is set to ""000"" in ""/etc/login.defs"" file, the Severity is raised to a CAT I.



# grep -i umask /etc/login.defs

UMASK  077



If the value for the ""UMASK"" parameter is not ""077"", or the ""UMASK"" parameter is missing or is commented out, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the operating system to define default permissions for all authenticated users in such a way that the user can only read and modify their own files.



Add or edit the line for the ""UMASK"" parameter in ""/etc/login.defs"" file to ""077"":



UMASK  077
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
