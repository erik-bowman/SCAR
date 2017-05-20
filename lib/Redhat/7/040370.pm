# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::040370
#
# VULN ID
#   V-72247
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86871r2_rule
#
# STIG ID
#   RHEL-07-040370
#
# RULE TITLE
#   The system must not permit direct logons to the root account using remote access via SSH.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::040370;

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
    return 'V-72247';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000480-GPOS-00227';
}

sub get_rule_id {
    return 'SV-86871r2_rule';
}

sub get_stig_id {
    return 'RHEL-07-040370';
}

sub get_rule_title {
    return
        'The system must not permit direct logons to the root account using remote access via SSH.';
}

sub get_discussion {
    return <<'DISCUSSION';
Even though the communications channel may be encrypted, an additional layer of security is gained by extending the policy of not logging on directly as root. In addition, logging on with a user-specific account provides individual accountability of actions performed on the system.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify remote access using SSH prevents users from logging on directly as root.



Check that SSH prevents users from logging on directly as root with the following command:



# grep -i permitrootlogin /etc/ssh/sshd_config

PermitRootLogin no



If the ""PermitRootLogin"" keyword is set to ""yes"", is missing, or is commented out, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure SSH to stop users from logging on remotely as the root user.



Edit the appropriate  ""/etc/ssh/sshd_config"" file to uncomment or add the line for the ""PermitRootLogin"" keyword and set its value to ""no"" (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor):



PermitRootLogin no



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
