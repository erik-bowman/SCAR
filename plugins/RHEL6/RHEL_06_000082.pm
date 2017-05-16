#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_06_000082
#
# VULN ID
#   V-38511
#
# SEVERITY
#   CAT II
#
# RULE ID
#   SV-50312r2_rule
#
# STIG ID
#   RHEL-06-000082
#
# RULE TITLE
#   IP forwarding for IPv4 must not be enabled, unless the system is a router.
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_06_000082;

# Standard pragmas
use utf8;
use strict;
use warnings FATAL => 'all';

# Plugin version
our $VERSION = 0.01;

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $plugin = RHEL_06_000082->new($core, $log, $backup, $parent);
#
# DESCRIPTION
#   Initializes the plugin object and returns it
#
# ARGUMENTS
#   $core      = The SCAR module object
#   $log       = The SCAR::Log module object
#   $backup    = The SCAR::Backup module object
#   $parent    = The SCAR::RHEL6 module object
#
# ------------------------------------------------------------------------------

sub new {
    my ( $class, $core, $log, $backup, $parent ) = @_;
    my $self = bless {
        core   => $core,
        log    => $log,
        backup => $backup,
        parent => $parent,
    }, $class;

    $self->{vuln_id}  = "V-38511";
    $self->{severity} = "CAT II";
    $self->{rule_id}  = "SV-50312r2_rule";
    $self->{stig_id}  = "RHEL-06-000082";
    $self->{rule_title}
        = "IP forwarding for IPv4 must not be enabled, unless the system is a router.";

    return $self;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   check
#
# DESCRIPTION
#
# ------------------------------------------------------------------------------

sub check {
    my ($self) = @_;
    if ( !defined $self->{parent}->{sysctl}->{"net.ipv4.ip_forward"}
        || $self->{parent}->{sysctl}->{"net.ipv4.ip_forward"} ne 0 )
    {
        $self->{results} = "O";
    }
    else {
        $self->{results} = "NF";
    }
    return $self->{results};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   remediate
#
# DESCRIPTION
#
# ------------------------------------------------------------------------------

sub remediate {
    my ($self) = @_;
    if ( $self->{backup}->check_backup("/etc/sysctl.conf") ) {
        $self->{log}->debug(
            "Skipping backup operation for '/etc/sysctl.conf': backup already exists"
        );
    }
    else {
        $self->{backup}->create("/etc/sysctl.conf");
    }
    my $remedition
        = $self->{parent}
        ->heal_sysctl_configuration( "net.ipv4.ip_forward", 0, $self->vuln_id,
        $self->severity, $self->vuln_id, $self->stig_id, $self->rule_title );
    $self->{log}
        ->remediation("Changes made to '/etc/sysctl.conf':\n\n$remedition");
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $vuln_id = RHEL_06_000082->vuln_id();
#
# DESCRIPTION
#   Returns the plugin vuln id
#
# ------------------------------------------------------------------------------

sub vuln_id {
    my ($self) = @_;
    return $self->{vuln_id};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $severity = RHEL_06_000082->severity();
#
# DESCRIPTION
#   Returns the plugin severity
#
# ------------------------------------------------------------------------------

sub severity {
    my ($self) = @_;
    return $self->{severity};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $rule_id = RHEL_06_000082->rule_id();
#
# DESCRIPTION
#   Returns the plugin rule id
#
# ------------------------------------------------------------------------------

sub rule_id {
    my ($self) = @_;
    return $self->{rule_id};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $stig_id = RHEL_06_000082->stig_id();
#
# DESCRIPTION
#   Returns the plugin stig id
#
# ------------------------------------------------------------------------------

sub stig_id {
    my ($self) = @_;
    return $self->{stig_id};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $rule_title = RHEL_06_000082->rule_title();
#
# DESCRIPTION
#   Returns the plugin rule title
#
# ------------------------------------------------------------------------------

sub rule_title {
    my ($self) = @_;
    return $self->{rule_title};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $discussion = RHEL_06_000082->discussion();
#
# DESCRIPTION
#   Returns the plugin discussion text
#
# ------------------------------------------------------------------------------

sub discussion {
    my ($self) = @_;
    $self->{discussion} = <<'DISCUSSION';
IP forwarding permits the kernel to forward packets from one network interface to another. The ability to forward packets between two networks is only appropriate for systems acting as routers.
DISCUSSION
    return $self->{discussion};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $check_content = RHEL_06_000082->check_content();
#
# DESCRIPTION
#   Returns the plugin check content text
#
# ------------------------------------------------------------------------------

sub check_content {
    my ($self) = @_;
    $self->{check_content} = <<'CHECKCONTENT';
The status of the "net.ipv4.ip_forward" kernel parameter can be queried by running the following command:

$ sysctl net.ipv4.ip_forward

The output of the command should indicate a value of "0". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf".

$ grep net.ipv4.ip_forward /etc/sysctl.conf

The ability to forward packets is only appropriate for routers. If the correct value is not returned, this is a finding.
CHECKCONTENT
    return $self->{check_content};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#    = RHEL_06_000082->fix_content();
#
# DESCRIPTION
#   Returns the plugin fix_content text
#
# ------------------------------------------------------------------------------

sub fix_content {
    my ($self) = @_;
    $self->{fix_content} = <<'FIXCONTENT';
To set the runtime status of the "net.ipv4.ip_forward" kernel parameter, run the following command:

# sysctl -w net.ipv4.ip_forward=0

If this is not the system's default value, add the following line to "/etc/sysctl.conf":

net.ipv4.ip_forward = 0
FIXCONTENT
    return $self->{fix_content};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#    = RHEL_06_000082->cci();
#
# DESCRIPTION
#   Returns the plugin cci text
#
# ------------------------------------------------------------------------------

sub cci {
    my ($self) = @_;
    $self->{cci} = <<'CCI';
CCI: CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b
CCI
    return $self->{cci};
}

# ------------------------------------------------------------------------------

1;

__END__
