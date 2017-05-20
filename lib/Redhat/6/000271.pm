# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000271
#
# VULN ID
#   V-38655
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000035
#
# RULE ID
#   SV-50456r1_rule
#
# STIG ID
#   RHEL-06-000271
#
# RULE TITLE
#   The noexec option must be added to removable media partitions.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000271;

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
    return 'V-38655';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-000035';
}

sub get_rule_id {
    return 'SV-50456r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000271';
}

sub get_rule_title {
    return 'The noexec option must be added to removable media partitions.';
}

sub get_discussion {
    return <<'DISCUSSION';
Allowing users to execute binaries from removable media such as USB keys exposes the system to potential compromise.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To verify that binaries cannot be directly executed from removable media, run the following command:



# grep noexec /etc/fstab



The output should show ""noexec"" in use.

If it does not, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
The ""noexec"" mount option prevents the direct execution of binaries on the mounted filesystem. Users should not be allowed to execute binaries that exist on partitions mounted from removable media (such as a USB key). The ""noexec"" option prevents code from being executed directly from the media itself, and may therefore provide a line of defense against certain types of worms or malicious code. Add the ""noexec"" option to the fourth column of ""/etc/fstab"" for the line which controls mounting of any removable media partitions.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000087

The organization disables information system functionality that provides the capability for automatic execution of code on mobile devices without user direction.

NIST SP 800-53 :: AC-19 e

NIST SP 800-53A :: AC-19.1 (v)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
