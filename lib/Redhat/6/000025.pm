# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000025
#
# VULN ID
#   V-51379
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-999999
#
# RULE ID
#   SV-65589r1_rule
#
# STIG ID
#   RHEL-06-000025
#
# RULE TITLE
#   All device files must be monitored by the system Linux Security Module.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000025;

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
    return 'V-51379';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-999999';
}

sub get_rule_id {
    return 'SV-65589r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000025';
}

sub get_rule_title {
    return
        'All device files must be monitored by the system Linux Security Module.';
}

sub get_discussion {
    return <<'DISCUSSION';
If a device file carries the SELinux type ""unlabeled_t"", then SELinux cannot properly restrict access to the device file.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To check for unlabeled device files, run the following command:



# ls -RZ /dev | grep unlabeled_t



It should produce no output in a well-configured system.



If there is output, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Device files, which are used for communication with important system resources, should be labeled with proper SELinux types. If any device files carry the SELinux type ""unlabeled_t"", investigate the cause and correct the file's context.
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
