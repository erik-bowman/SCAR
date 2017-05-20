# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::020200
#
# VULN ID
#   V-71987
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000437-GPOS-00194
#
# RULE ID
#   SV-86611r1_rule
#
# STIG ID
#   RHEL-07-020200
#
# RULE TITLE
#   The operating system must remove all software components after updated versions have been installed.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::020200;

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
    return 'V-71987';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-000437-GPOS-00194';
}

sub get_rule_id {
    return 'SV-86611r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-020200';
}

sub get_rule_title {
    return
        'The operating system must remove all software components after updated versions have been installed.';
}

sub get_discussion {
    return <<'DISCUSSION';
Previous versions of software components that are not removed from the information system after updates have been installed may be exploited by adversaries. Some information technology products may remove older versions of software automatically from the information system.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the operating system removes all software components after updated versions have been installed.



Check if yum is configured to remove unneeded packages with the following command:



# grep -i clean_requirements_on_remove /etc/yum.conf

clean_requirements_on_remove=1



If ""clean_requirements_on_remove"" is not set to ""1"", ""True"", or ""yes"", or is not set in ""/etc/yum.conf"", this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the operating system to remove all software components after updated versions have been installed.



Set the ""clean_requirements_on_remove"" option to ""1"" in the ""/etc/yum.conf"" file:



clean_requirements_on_remove=1
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-002617

The organization removes organization-defined software components (e.g., previous versions) after updated versions have been installed.

NIST SP 800-53 Revision 4 :: SI-2 (6)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
