#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_06_000203
#
# VULN ID
#   V-38582
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000096
#
# RULE ID
#   SV-50383r2_rule
#
# STIG ID
#   RHEL-06-000203
#
# RULE TITLE
#   The xinetd service must be disabled if no network services utilizing it are enabled.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_06_000203;

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
    $self->{VULN_ID} = 'V-38582';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000096';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50383r2_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000203';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The xinetd service must be disabled if no network services utilizing it are enabled.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
The xinetd service provides a dedicated listener service for some programs, which is no longer necessary for commonly-used network services. Disabling it ensures that these uncommon services are not running, and also prevents attacks against xinetd itself.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
If network services are using the xinetd service, this is not applicable.



To check that the ""xinetd"" service is disabled in system boot configuration, run the following command:



# chkconfig ""xinetd"" --list



Output should indicate the ""xinetd"" service has either not been installed, or has been disabled at all runlevels, as shown in the example below:



# chkconfig ""xinetd"" --list

""xinetd"" 0:off 1:off 2:off 3:off 4:off 5:off 6:off



Run the following command to verify ""xinetd"" is disabled through current runtime configuration:



# service xinetd status



If the service is disabled the command will return the following output:



xinetd is stopped





If the service is running, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
The ""xinetd"" service can be disabled with the following commands:



# chkconfig xinetd off

# service xinetd stop
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000382

The organization configures the information system to prohibit or restrict the use of organization defined functions, ports, protocols, and/or services.

NIST SP 800-53 :: CM-7

NIST SP 800-53A :: CM-7.1 (iii)

NIST SP 800-53 Revision 4 :: CM-7 b




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
