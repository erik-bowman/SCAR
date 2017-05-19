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

sub VULN_ID {
    my ($self) = @_;
    $self->{VULN_ID} = 'V-38481';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000191';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50281r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000011';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'System security patches and updates must be installed and up-to-date.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Installing software updates is a fundamental mitigation against the exploitation of publicly-known vulnerabilities.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
If the system is joined to the Red Hat Network, a Red Hat Satellite Server, or a yum server which provides updates, invoking the following command will indicate if updates are available:



# yum check-update



If the system is not configured to update from one of these sources, run the following command to list when each package was last updated:



$ rpm -qa -last



Compare this to Red Hat Security Advisories (RHSA) listed at https://access.redhat.com/security/updates/active/ to determine whether the system is missing applicable security and bugfix  updates.

If updates are not installed, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
If the system is joined to the Red Hat Network, a Red Hat Satellite Server, or a yum server, run the following command to install updates:



# yum update



If the system is not configured to use one of these sources, updates (in the form of RPM packages) can be manually downloaded from the Red Hat Network and installed using ""rpm"".
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-001233

The organization employs automated mechanisms on an organization-defined frequency to determine the state of information system components with regard to flaw remediation.

NIST SP 800-53 :: SI-2 (2)

NIST SP 800-53A :: SI-2 (2).1 (ii)

NIST SP 800-53 Revision 4 :: SI-2 (2)




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
