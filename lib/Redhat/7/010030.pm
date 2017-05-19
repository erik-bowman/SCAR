# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::010030
#
# VULN ID
#   V-71859
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000023-GPOS-00006
#
# RULE ID
#   SV-86483r2_rule
#
# STIG ID
#   RHEL-07-010030
#
# RULE TITLE
#   The operating system must display the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a graphical user logon.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::010030;

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
    $self->{VULN_ID} = 'V-71859';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000023-GPOS-00006';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-86483r2_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-010030';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The operating system must display the Standard Mandatory DoD Notice and Consent Banner before granting local or remote access to the system via a graphical user logon.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Display of a standardized and approved use notification before granting access to the operating system ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.



System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist.



The banner must be formatted in accordance with applicable DoD policy. Use the following verbiage for operating systems that can accommodate banners of 1300 characters:



""You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.



By using this IS (which includes any device attached to this IS), you consent to the following conditions:



-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.



-At any time, the USG may inspect and seize data stored on this IS.



-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.



-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.



-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.""



Use the following verbiage for operating systems that have severe limitations on the number of characters that can be displayed in the banner:



""I've read & consent to terms in IS user agreem't.""



Satisfies: SRG-OS-000023-GPOS-00006, SRG-OS-000024-GPOS-00007, SRG-OS-000228-GPOS-00088
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Verify the operating system displays the Standard Mandatory DoD Notice and Consent Banner before granting access to the operating system via a graphical user logon.



Note: If the system does not have GNOME installed, this requirement is Not Applicable.



Check to see if the operating system displays a banner at the logon screen with the following command:



# grep banner-message-enable /etc/dconf/db/local.d/*

banner-message-enable=true



If ""banner-message-enable"" is set to ""false"" or is missing, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Configure the operating system to display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system.



Note: If the system does not have GNOME installed, this requirement is Not Applicable.



Create a database to contain the system-wide graphical user logon settings (if it does not already exist) with the following command:



# touch /etc/dconf/db/local.d/01-banner-message



Add the following line to the [org/gnome/login-screen] section of the ""/etc/dconf/db/local.d/01-banner-message"":



[org/gnome/login-screen]

banner-message-enable=true
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000048

The information system displays an organization-defined system use notification message or banner before granting access to the system that provides privacy and security notices consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

NIST SP 800-53 :: AC-8 a

NIST SP 800-53A :: AC-8.1 (ii)

NIST SP 800-53 Revision 4 :: AC-8 a




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
