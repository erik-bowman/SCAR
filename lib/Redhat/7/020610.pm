# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::020610
#
# VULN ID
#   V-72013
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86637r1_rule
#
# STIG ID
#   RHEL-07-020610
#
# RULE TITLE
#   All local interactive user accounts, upon creation, must be assigned a home directory.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::020610;

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
    return 'V-72013';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000480-GPOS-00227';
}

sub get_rule_id {
    return 'SV-86637r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-020610';
}

sub get_rule_title {
    return
        'All local interactive user accounts, upon creation, must be assigned a home directory.';
}

sub get_discussion {
    return <<'DISCUSSION';
If local interactive users are not assigned a valid home directory, there is no place for the storage and control of files they should own.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify all local interactive users on the system are assigned a home directory upon creation.



Check to see if the system is configured to create home directories for local interactive users with the following command:



# grep -i create_home /etc/login.defs

CREATE_HOME yes



If the value for ""CREATE_HOME"" parameter is not set to ""yes"", the line is missing, or the line is commented out, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the operating system to assign home directories to all new local interactive users by setting the ""CREATE_HOME"" parameter in ""/etc/login.defs"" to ""yes"" as follows.



CREATE_HOME yes
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
