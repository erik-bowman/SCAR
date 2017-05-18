#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_06_000507
#
# VULN ID
#   V-38484
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000025
#
# RULE ID
#   SV-50285r2_rule
#
# STIG ID
#   RHEL-06-000507
#
# RULE TITLE
#   The operating system, upon successful logon, must display to the user the date and time of the last logon or access via ssh.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_06_000507;

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
    $self->{VULN_ID} = 'V-38484';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000025';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50285r2_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000507';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The operating system, upon successful logon, must display to the user the date and time of the last logon or access via ssh.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Users need to be aware of activity that occurs regarding their account. Providing users with information regarding the date and time of their last successful login allows the user to determine if any unauthorized activity has occurred and gives them an opportunity to notify administrators.



At ssh login, a user must be presented with the last successful login date and time.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Verify the value associated with the ""PrintLastLog"" keyword in /etc/ssh/sshd_config:



# grep -i ""^PrintLastLog"" /etc/ssh/sshd_config



If the ""PrintLastLog"" keyword is not present, this is not a finding.  If the value is not set to ""yes"", this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Update the ""PrintLastLog"" keyword to ""yes"" in /etc/ssh/sshd_config:



PrintLastLog yes



While it is acceptable to remove the keyword entirely since the default action for the SSH daemon is to print the last logon date and time, it is preferred to have the value explicitly documented.
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000052

The information system notifies the user, upon successful logon (access) to the system, of the date and time of the last logon (access).

NIST SP 800-53 :: AC-9

NIST SP 800-53A :: AC-9.1

NIST SP 800-53 Revision 4 :: AC-9




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
