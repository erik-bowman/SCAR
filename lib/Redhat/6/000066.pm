# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000066
#
# VULN ID
#   V-38581
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-999999
#
# RULE ID
#   SV-50382r2_rule
#
# STIG ID
#   RHEL-06-000066
#
# RULE TITLE
#   The system boot loader configuration file(s) must be group-owned by root.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000066;

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
    return 'V-38581';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-999999';
}

sub get_rule_id {
    return 'SV-50382r2_rule';
}

sub get_stig_id {
    return 'RHEL-06-000066';
}

sub get_rule_title {
    return
        'The system boot loader configuration file(s) must be group-owned by root.';
}

sub get_discussion {
    return <<'DISCUSSION';
The ""root"" group is a highly-privileged group. Furthermore, the group-owner of this file should not have any access privileges anyway.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To check the group ownership of ""/boot/grub/grub.conf"", run the command:



$ ls -lL /boot/grub/grub.conf



If properly configured, the output should indicate the group-owner is ""root"".

If it does not, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
The file ""/boot/grub/grub.conf"" should be group-owned by the ""root"" group to prevent destruction or modification of the file. To properly set the group owner of ""/boot/grub/grub.conf"", run the command:



# chgrp root /boot/grub/grub.conf
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
