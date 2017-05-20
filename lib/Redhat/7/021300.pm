# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::021300
#
# VULN ID
#   V-72057
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86681r1_rule
#
# STIG ID
#   RHEL-07-021300
#
# RULE TITLE
#   Kernel core dumps must be disabled unless needed.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::021300;

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
    return 'V-72057';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000480-GPOS-00227';
}

sub get_rule_id {
    return 'SV-86681r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-021300';
}

sub get_rule_title {
    return 'Kernel core dumps must be disabled unless needed.';
}

sub get_discussion {
    return <<'DISCUSSION';
Kernel core dumps may contain the full contents of system memory at the time of the crash. Kernel core dumps may consume a considerable amount of disk space and may result in denial of service by exhausting the available space on the target file system partition.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify that kernel core dumps are disabled unless needed.



Check the status of the ""kdump"" service with the following command:



# systemctl status kdump.service

kdump.service - Crash recovery kernel arming

   Loaded: loaded (/usr/lib/systemd/system/kdump.service; enabled)

   Active: active (exited) since Wed 2015-08-26 13:08:09 EDT; 43min ago

 Main PID: 1130 (code=exited, status=0/SUCCESS)

kernel arming.



If the ""kdump"" service is active, ask the System Administrator if the use of the service is required and documented with the Information System Security Officer (ISSO).



If the service is active and is not documented, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
If kernel core dumps are not required, disable the ""kdump"" service with the following command:



# systemctl disable kdump.service



If kernel core dumps are required, document the need with the ISSO.
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
