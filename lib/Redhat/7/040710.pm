# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::040710
#
# VULN ID
#   V-72303
#
# SEVERITY
#   high
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86927r2_rule
#
# STIG ID
#   RHEL-07-040710
#
# RULE TITLE
#   Remote X connections for interactive users must be encrypted.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::040710;

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
    return 'V-72303';
}

sub get_severity {
    return 'high';
}

sub get_group_title {
    return 'SRG-OS-000480-GPOS-00227';
}

sub get_rule_id {
    return 'SV-86927r2_rule';
}

sub get_stig_id {
    return 'RHEL-07-040710';
}

sub get_rule_title {
    return 'Remote X connections for interactive users must be encrypted.';
}

sub get_discussion {
    return <<'DISCUSSION';
Open X displays allow an attacker to capture keystrokes and execute commands remotely.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify remote X connections for interactive users are encrypted.



Check that remote X connections are encrypted with the following command:



# grep -i x11forwarding /etc/ssh/sshd_config

X11Fowarding yes



If the ""X11Forwarding"" keyword is set to ""no"", is missing, or is commented out, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure SSH to encrypt connections for interactive users.



Edit the ""/etc/ssh/sshd_config"" file to uncomment or add the line for the ""X11Forwarding"" keyword and set its value to ""yes"" (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor):



X11Fowarding yes



The SSH service must be restarted for changes to take effect.
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
