# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000290
#
# VULN ID
#   V-38674
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000248
#
# RULE ID
#   SV-50475r1_rule
#
# STIG ID
#   RHEL-06-000290
#
# RULE TITLE
#   X Windows must not be enabled unless required.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000290;

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
    return 'V-38674';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000248';
}

sub get_rule_id {
    return 'SV-50475r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000290';
}

sub get_rule_title {
    return 'X Windows must not be enabled unless required.';
}

sub get_discussion {
    return <<'DISCUSSION';
Unnecessary services should be disabled to decrease the attack surface of the system.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To verify the default runlevel is 3, run the following command:



# grep initdefault /etc/inittab



The output should show the following:



id:3:initdefault:





If it does not, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Setting the system's runlevel to 3 will prevent automatic startup of the X server. To do so, ensure the following line in ""/etc/inittab"" features a ""3"" as shown:



id:3:initdefault:
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-001436

The organization disables organization defined networking protocols within the information system deemed to be nonsecure except for explicitly identified components in support of specific operational requirements.

NIST SP 800-53 :: AC-17 (8)

NIST SP 800-53A :: AC-17 (8).1 (ii)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
