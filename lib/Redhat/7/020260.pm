# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::020260
#
# VULN ID
#   V-71999
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86623r3_rule
#
# STIG ID
#   RHEL-07-020260
#
# RULE TITLE
#   Vendor packaged system security patches and updates must be installed and up to date.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::020260;

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
    return 'V-71999';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000480-GPOS-00227';
}

sub get_rule_id {
    return 'SV-86623r3_rule';
}

sub get_stig_id {
    return 'RHEL-07-020260';
}

sub get_rule_title {
    return
        'Vendor packaged system security patches and updates must be installed and up to date.';
}

sub get_discussion {
    return <<'DISCUSSION';
Timely patching is critical for maintaining the operational availability, confidentiality, and integrity of information technology (IT) systems. However, failure to keep operating system and application software patched is a common mistake made by IT professionals. New patches are released daily, and it is often difficult for even experienced System Administrators to keep abreast of all the new patches. When new weaknesses in an operating system exist, patches are usually made available by the vendor to resolve the problems. If the most recent security patches and updates are not installed, unauthorized users may take advantage of weaknesses in the unpatched software. The lack of prompt attention to patching could result in a system compromise.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the operating system security patches and updates are installed and up to date. Updates are required to be applied with a frequency determined by the site or Program Management Office (PMO).



Obtain the list of available package security updates from Red Hat. The URL for updates is https://rhn.redhat.com/errata/. It is important to note that updates provided by Red Hat may not be present on the system if the underlying packages are not installed.



Check that the available package security updates have been installed on the system with the following command:



# yum history list | more

Loaded plugins: langpacks, product-id, subscription-manager

ID     | Command line             | Date and time    | Action(s)      | Altered

-------------------------------------------------------------------------------

    70 | install aide             | 2016-05-05 10:58 | Install       |     1

    69 | update -y                | 2016-05-04 14:34 | Update     |   18 EE

    68 | install vlc                | 2016-04-21 17:12 | Install        |   21

    67 | update -y                | 2016-04-21 17:04 | Update     |     7 EE

    66 | update -y                | 2016-04-15 16:47 | E, I, U         |   84 EE



If package updates have not been performed on the system within the timeframe that the site/program documentation requires, this is a finding.



Typical update frequency may be overridden by Information Assurance Vulnerability Alert (IAVA) notifications from CYBERCOM.



If the operating system is in non-compliance with the Information Assurance Vulnerability Management (IAVM) process, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Install the operating system patches or updated packages available from Red Hat within 30 days or sooner as local policy dictates.
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
