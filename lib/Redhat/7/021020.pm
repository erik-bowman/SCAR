# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::021020
#
# VULN ID
#   V-72045
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86669r1_rule
#
# STIG ID
#   RHEL-07-021020
#
# RULE TITLE
#   File systems that are being imported via Network File System (NFS) must be mounted to prevent files with the setuid and setgid bit set from being executed.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::021020;

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
    return 'V-72045';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000480-GPOS-00227';
}

sub get_rule_id {
    return 'SV-86669r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-021020';
}

sub get_rule_title {
    return
        'File systems that are being imported via Network File System (NFS) must be mounted to prevent files with the setuid and setgid bit set from being executed.';
}

sub get_discussion {
    return <<'DISCUSSION';
The ""nosuid"" mount option causes the system to not execute ""setuid"" and ""setgid"" files with owner privileges. This option must be used for mounting any file system not containing approved ""setuid"" and ""setguid"" files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify file systems that are being NFS exported are mounted with the ""nosuid"" option.



Find the file system(s) that contain the directories being exported with the following command:



# more /etc/fstab | grep nfs



UUID=e06097bb-cfcd-437b-9e4d-a691f5662a7d    /store           nfs           rw,nosuid                                                    0 0



If a file system found in ""/etc/fstab"" refers to NFS and it does not have the ""nosuid"" option set, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the ""/etc/fstab"" to use the ""nosuid"" option on file systems that are being exported via NFS.
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
