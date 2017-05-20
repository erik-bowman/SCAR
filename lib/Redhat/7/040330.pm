# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::040330
#
# VULN ID
#   V-72239
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86863r2_rule
#
# STIG ID
#   RHEL-07-040330
#
# RULE TITLE
#   The SSH daemon must not allow authentication using RSA rhosts authentication.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::040330;

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
    return 'V-72239';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000480-GPOS-00227';
}

sub get_rule_id {
    return 'SV-86863r2_rule';
}

sub get_stig_id {
    return 'RHEL-07-040330';
}

sub get_rule_title {
    return
        'The SSH daemon must not allow authentication using RSA rhosts authentication.';
}

sub get_discussion {
    return <<'DISCUSSION';
Configuring this setting for the SSH daemon provides additional assurance that remote logon via SSH will require a password, even in the event of misconfiguration elsewhere.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the SSH daemon does not allow authentication using RSA rhosts authentication.



To determine how the SSH daemon's ""RhostsRSAAuthentication"" option is set, run the following command:



# grep RhostsRSAAuthentication /etc/ssh/sshd_config



RhostsRSAAuthentication yes



If the value is returned as ""no"", the returned line is commented out, or no output is returned, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the SSH daemon to not allow authentication using RSA rhosts authentication.



Add the following line in ""/etc/ssh/sshd_config"", or uncomment the line and set the value to ""yes"":



RhostsRSAAuthentication yes



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
