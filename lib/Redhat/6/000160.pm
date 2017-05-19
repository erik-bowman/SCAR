# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000160
#
# VULN ID
#   V-38633
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-999999
#
# RULE ID
#   SV-50434r1_rule
#
# STIG ID
#   RHEL-06-000160
#
# RULE TITLE
#   The system must set a maximum audit log file size.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000160;

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

sub VULN_ID {
    my ($self) = @_;
    $self->{VULN_ID} = 'V-38633';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-999999';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50434r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000160';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The system must set a maximum audit log file size.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
The total storage for audit log files must be large enough to retain log information over the period required. This is a function of the maximum log file size and the number of logs retained.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Inspect ""/etc/audit/auditd.conf"" and locate the following line to determine how much data the system will retain in each audit log file: ""# grep max_log_file /etc/audit/auditd.conf""



max_log_file = 6





If the system audit data threshold hasn't been properly set up, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Determine the amount of audit data (in megabytes) which should be retained in each log file. Edit the file ""/etc/audit/auditd.conf"". Add or modify the following line, substituting the correct value for [STOREMB]:



max_log_file = [STOREMB]



Set the value to ""6"" (MB) or higher for general-purpose systems. Larger values, of course, support retention of even more audit data.
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
