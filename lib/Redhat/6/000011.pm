# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000011
#
# VULN ID
#   V-38481
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000191
#
# RULE ID
#   SV-50281r1_rule
#
# STIG ID
#   RHEL-06-000011
#
# RULE TITLE
#   System security patches and updates must be installed and up-to-date.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000011;

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
    return 'V-38481';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000191';
}

sub get_rule_id {
    return 'SV-50281r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000011';
}

sub get_rule_title {
    return
        'System security patches and updates must be installed and up-to-date.';
}

sub get_discussion {
    return <<'DISCUSSION';
Installing software updates is a fundamental mitigation against the exploitation of publicly-known vulnerabilities.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
If the system is joined to the Red Hat Network, a Red Hat Satellite Server, or a yum server which provides updates, invoking the following command will indicate if updates are available:



# yum check-update



If the system is not configured to update from one of these sources, run the following command to list when each package was last updated:



$ rpm -qa -last



Compare this to Red Hat Security Advisories (RHSA) listed at https://access.redhat.com/security/updates/active/ to determine whether the system is missing applicable security and bugfix  updates.

If updates are not installed, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
If the system is joined to the Red Hat Network, a Red Hat Satellite Server, or a yum server, run the following command to install updates:



# yum update



If the system is not configured to use one of these sources, updates (in the form of RPM packages) can be manually downloaded from the Red Hat Network and installed using ""rpm"".
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-001233

The organization employs automated mechanisms on an organization-defined frequency to determine the state of information system components with regard to flaw remediation.

NIST SP 800-53 :: SI-2 (2)

NIST SP 800-53A :: SI-2 (2).1 (ii)

NIST SP 800-53 Revision 4 :: SI-2 (2)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
