# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000223
#
# VULN ID
#   V-38609
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000248
#
# RULE ID
#   SV-50410r2_rule
#
# STIG ID
#   RHEL-06-000223
#
# RULE TITLE
#   The TFTP service must not be running.
#
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000223;

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
    if ( !defined $self->{parent}->{service}->{'tftp-server'} ) {
        $self->{STATUS} = 'NF';
    }
    else {
        if ( $self->{parent}->{service}->{'tftp-server'}->{status}
            =~ /^tftp-server\sis\sstopped/msx )
        {
            $self->{STATUS} = 'NF';
        }
        else {
            $self->{STATUS} = 'O';
        }
    }
    return $self;
}

sub remediate {
    my ($self) = @_;

    return $self;
}

sub VULN_ID {
    my ($self) = @_;
    $self->{VULN_ID} = 'V-38609';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000248';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50410r2_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000223';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE} = 'The TFTP service must not be running.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Disabling the ""tftp"" service ensures the system is not acting as a tftp server, which does not provide encryption or authentication.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
To check that the ""tftp"" service is disabled in system boot configuration, run the following command:



# chkconfig ""tftp"" --list



Output should indicate the ""tftp"" service has either not been installed, or has been disabled, as shown in the example below:



# chkconfig ""tftp"" --list

tftp off

OR

error reading information on service tftp: No such file or directory





If the service is running, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
The ""tftp"" service should be disabled. The ""tftp"" service can be disabled with the following command:



# chkconfig tftp off
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-001436

The organization disables organization defined networking protocols within the information system deemed to be nonsecure except for explicitly identified components in support of specific operational requirements.

NIST SP 800-53 :: AC-17 (8)

NIST SP 800-53A :: AC-17 (8).1 (ii)




CCI
    return $self->{CCI};
}

1;

__END__
