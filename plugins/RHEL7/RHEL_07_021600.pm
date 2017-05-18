#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_07_021600
#
# VULN ID
#   V-72069
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86693r2_rule
#
# STIG ID
#   RHEL-07-021600
#
# RULE TITLE
#   The file integrity tool must be configured to verify Access Control Lists (ACLs).
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_07_021600;

# Standard modules
use utf8;
use strict;
use warnings FATAL => 'all';

# SCAR modules
use SCAR;
use SCAR::Log;
use SCAR::Backup;

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

sub VULN_ID {
    my ($self) = @_;
    $self->{VULN_ID} = 'V-72069';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'low';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000480-GPOS-00227';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-86693r2_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-021600';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The file integrity tool must be configured to verify Access Control Lists (ACLs).';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
ACLs can provide permissions beyond those permitted through the file mode and must be verified by file integrity tools.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Verify the file integrity tool is configured to verify ACLs.



Check to see if Advanced Intrusion Detection Environment (AIDE) is installed on the system with the following command:



# yum list installed aide



If AIDE is not installed, ask the System Administrator how file integrity checks are performed on the system.



If there is no application installed to perform file integrity checks, this is a finding.



Note: AIDE is highly configurable at install time. These commands assume the ""aide.conf"" file is under the ""/etc"" directory.



Use the following command to determine if the file is in another location:



# find / -name aide.conf



Check the ""aide.conf"" file to determine if the ""acl"" rule has been added to the rule list being applied to the files and directories selection lists.



An example rule that includes the ""acl"" rule is below:



All= p+i+n+u+g+s+m+S+sha512+acl+xattrs+selinux

/bin All            # apply the custom rule to the files in bin

/sbin All          # apply the same custom rule to the files in sbin



If the ""acl"" rule is not being used on all selection lines in the ""/etc/aide.conf"" file, or ACLs are not being checked by another file integrity tool, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Configure the file integrity tool to check file and directory ACLs.



If AIDE is installed, ensure the ""acl"" rule is present on all file and directory selection lists.
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000366

The organization implements the security configuration settings.

NIST SP 800-53 :: CM-6 b

NIST SP 800-53A :: CM-6.1 (iv)

NIST SP 800-53 Revision 4 :: CM-6 b




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
