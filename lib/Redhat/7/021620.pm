# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::021620
#
# VULN ID
#   V-72073
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86697r2_rule
#
# STIG ID
#   RHEL-07-021620
#
# RULE TITLE
#   The file integrity tool must use FIPS 140-2 approved cryptographic hashes for validating file contents and directories.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::021620;

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
    return 'V-72073';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000480-GPOS-00227';
}

sub get_rule_id {
    return 'SV-86697r2_rule';
}

sub get_stig_id {
    return 'RHEL-07-021620';
}

sub get_rule_title {
    return
        'The file integrity tool must use FIPS 140-2 approved cryptographic hashes for validating file contents and directories.';
}

sub get_discussion {
    return <<'DISCUSSION';
File integrity tools use cryptographic hashes for verifying file contents and directories have not been altered. These hashes must be FIPS 140-2 approved cryptographic hashes.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the file integrity tool is configured to use FIPS 140-2 approved cryptographic hashes for validating file contents and directories.



Note: If RHEL-07-021350 is a finding, this is automatically a finding as the system cannot implement FIPS 140-2 approved cryptographic algorithms and hashes.



Check to see if Advanced Intrusion Detection Environment (AIDE) is installed on the system with the following command:



# yum list installed aide



If AIDE is not installed, ask the System Administrator how file integrity checks are performed on the system.



If there is no application installed to perform file integrity checks, this is a finding.



Note: AIDE is highly configurable at install time. These commands assume the ""aide.conf"" file is under the ""/etc"" directory.



Use the following command to determine if the file is in another location:



# find / -name aide.conf



Check the ""aide.conf"" file to determine if the ""sha512"" rule has been added to the rule list being applied to the files and directories selection lists.



An example rule that includes the ""sha512"" rule follows:



All=p+i+n+u+g+s+m+S+sha512+acl+xattrs+selinux

/bin All            # apply the custom rule to the files in bin

/sbin All          # apply the same custom rule to the files in sbin



If the ""sha512"" rule is not being used on all selection lines in the ""/etc/aide.conf"" file, or another file integrity tool is not using FIPS 140-2 approved cryptographic hashes for validating file contents and directories, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the file integrity tool to use FIPS 140-2 cryptographic hashes for validating file and directory contents.



If AIDE is installed, ensure the ""sha512"" rule is present on all file and directory selection lists.
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