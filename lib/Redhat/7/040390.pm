# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::040390
#
# VULN ID
#   V-72251
#
# SEVERITY
#   high
#
# GROUP TITLE
#   SRG-OS-000074-GPOS-00042
#
# RULE ID
#   SV-86875r2_rule
#
# STIG ID
#   RHEL-07-040390
#
# RULE TITLE
#   The SSH daemon must be configured to only use the SSHv2 protocol.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::040390;

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
    return 'V-72251';
}

sub get_severity {
    return 'high';
}

sub get_group_title {
    return 'SRG-OS-000074-GPOS-00042';
}

sub get_rule_id {
    return 'SV-86875r2_rule';
}

sub get_stig_id {
    return 'RHEL-07-040390';
}

sub get_rule_title {
    return
        'The SSH daemon must be configured to only use the SSHv2 protocol.';
}

sub get_discussion {
    return <<'DISCUSSION';
SSHv1 is an insecure implementation of the SSH protocol and has many well-known vulnerability exploits. Exploits of the SSH daemon could provide immediate root access to the system.



Satisfies: SRG-OS-000074-GPOS-00042, SRG-OS-000480-GPOS-00227
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the SSH daemon is configured to only use the SSHv2 protocol.



Check that the SSH daemon is configured to only use the SSHv2 protocol with the following command:



# grep -i protocol /etc/ssh/sshd_config

Protocol 2

#Protocol 1,2



If any protocol line other than ""Protocol 2"" is uncommented, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Remove all Protocol lines that reference version ""1"" in ""/etc/ssh/sshd_config"" (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor). The ""Protocol"" line must be as follows:



Protocol 2



The SSH service must be restarted for changes to take effect.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000197

The information system, for password-based authentication, transmits only encrypted representations of passwords.

NIST SP 800-53 :: IA-5 (1) (c)

NIST SP 800-53A :: IA-5 (1).1 (v)

NIST SP 800-53 Revision 4 :: IA-5 (1) (c)



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
