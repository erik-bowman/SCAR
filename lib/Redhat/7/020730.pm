# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::020730
#
# VULN ID
#   V-72037
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86661r1_rule
#
# STIG ID
#   RHEL-07-020730
#
# RULE TITLE
#   Local initialization files must not execute world-writable programs.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::020730;

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
    return 'V-72037';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000480-GPOS-00227';
}

sub get_rule_id {
    return 'SV-86661r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-020730';
}

sub get_rule_title {
    return
        'Local initialization files must not execute world-writable programs.';
}

sub get_discussion {
    return <<'DISCUSSION';
If user start-up files execute world-writable programs, especially in unprotected directories, they could be maliciously modified to destroy user files or otherwise compromise the system at the user level. If the system is compromised at the user level, it is easier to elevate privileges to eventually compromise the system at the root and network level.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify that local initialization files do not execute world-writable programs.



Check the system for world-writable files with the following command:



# find / -perm -002 -type f -exec ls -ld {} \; | more



For all files listed, check for their presence in the local initialization files with the following commands:



Note: The example will be for a system that is configured to create users’ home directories in the ""/home"" directory.



# grep <file> /home/*/.*



If any local initialization files are found to reference world-writable files, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Set the mode on files being executed by the local initialization files with the following command:



# chmod 0755  <file>
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