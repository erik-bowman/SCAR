# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000248
#
# VULN ID
#   V-38621
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000056
#
# RULE ID
#   SV-50422r1_rule
#
# STIG ID
#   RHEL-06-000248
#
# RULE TITLE
#   The system clock must be synchronized to an authoritative DoD time source.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000248;

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
    $self->{VULN_ID} = 'V-38621';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000056';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50422r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000248';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The system clock must be synchronized to an authoritative DoD time source.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Synchronizing with an NTP server makes it possible to collate system logs from multiple sources or correlate computer events with real time events. Using a trusted NTP server provided by your organization is recommended.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
A remote NTP server should be configured for time synchronization. To verify one is configured, open the following file.



/etc/ntp.conf



In the file, there should be a section similar to the following:



# --- OUR TIMESERVERS -----

server [ntpserver]





If this is not the case, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
To specify a remote NTP server for time synchronization, edit the file ""/etc/ntp.conf"". Add or correct the following lines, substituting the IP or hostname of a remote NTP server for ntpserver.



server [ntpserver]



This instructs the NTP software to contact that remote server to obtain time data.
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000160

The information system synchronizes internal information system clocks on an organization defined frequency with an organization defined authoritative time source.

NIST SP 800-53 :: AU-8 (1)

NIST SP 800-53A :: AU-8 (1).1 (iii)




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
