# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000078
#
# VULN ID
#   V-38596
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-999999
#
# RULE ID
#   SV-50397r2_rule
#
# STIG ID
#   RHEL-06-000078
#
# RULE TITLE
#   The system must implement virtual address space randomization.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000078;

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
    return 'V-38596';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-999999';
}

sub get_rule_id {
    return 'SV-50397r2_rule';
}

sub get_stig_id {
    return 'RHEL-06-000078';
}

sub get_rule_title {
    return 'The system must implement virtual address space randomization.';
}

sub get_discussion {
    return <<'DISCUSSION';
Address space layout randomization (ASLR) makes it more difficult for an attacker to predict the location of attack code he or she has introduced into a process's address space during an attempt at exploitation. Additionally, ASLR also makes it more difficult for an attacker to know the location of existing code in order to repurpose it using return oriented programming (ROP) techniques.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
The status of the ""kernel.randomize_va_space"" kernel parameter can be queried by running the following commands:



$ sysctl kernel.randomize_va_space

$ grep kernel.randomize_va_space /etc/sysctl.conf



The output of the command should indicate a value of at least ""1"" (preferably ""2""). If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in ""/etc/sysctl.conf"".

If the correct value is not returned, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
To set the runtime status of the ""kernel.randomize_va_space"" kernel parameter, run the following command:



# sysctl -w kernel.randomize_va_space=2



If this is not the system's default value, add the following line to ""/etc/sysctl.conf"":



kernel.randomize_va_space = 2
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
