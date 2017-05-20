# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::010460
#
# VULN ID
#   V-71957
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00229
#
# RULE ID
#   SV-86581r2_rule
#
# STIG ID
#   RHEL-07-010460
#
# RULE TITLE
#   The operating system must not allow users to override SSH environment variables.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::010460;

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
    return 'V-71957';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000480-GPOS-00229';
}

sub get_rule_id {
    return 'SV-86581r2_rule';
}

sub get_stig_id {
    return 'RHEL-07-010460';
}

sub get_rule_title {
    return
        'The operating system must not allow users to override SSH environment variables.';
}

sub get_discussion {
    return <<'DISCUSSION';
Failure to restrict system access to authenticated users negatively impacts operating system security.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the operating system does not allow users to override environment variables to the SSH daemon.



Check for the value of the ""PermitUserEnvironment"" keyword with the following command:



# grep -i permituserenvironment /etc/ssh/sshd_config

PermitUserEnvironment no



If the ""PermitUserEnvironment"" keyword is not set to ""no"", is missing, or is commented out, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the operating system to not allow users to override environment variables to the SSH daemon.



Edit the ""/etc/ssh/sshd_config"" file to uncomment or add the line for ""PermitUserEnvironment"" keyword and set the value to ""no"":



PermitUserEnvironment no



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
