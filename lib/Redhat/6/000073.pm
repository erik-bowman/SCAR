# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000073
#
# VULN ID
#   V-38593
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000228
#
# RULE ID
#   SV-50394r3_rule
#
# STIG ID
#   RHEL-06-000073
#
# RULE TITLE
#   The Department of Defense (DoD) login banner must be displayed immediately prior to, or as part of, console login prompts.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000073;

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
    return 'V-38593';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000228';
}

sub get_rule_id {
    return 'SV-50394r3_rule';
}

sub get_stig_id {
    return 'RHEL-06-000073';
}

sub get_rule_title {
    return
        'The Department of Defense (DoD) login banner must be displayed immediately prior to, or as part of, console login prompts.';
}

sub get_discussion {
    return <<'DISCUSSION';
An appropriate warning message reinforces policy awareness during the logon process and facilitates possible legal action against attackers.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To check if the system login banner is compliant, run the following command:



$ cat /etc/issue





Note: The full text banner must be implemented unless there are character limitations that prevent the display of the full DoD logon banner.



If the required DoD logon banner is not displayed, this is a finding.


CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
To configure the system login banner:



Edit ""/etc/issue"". Replace the default text with a message compliant with the local site policy or a legal disclaimer. The DoD required text is either:



""You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.""



If the device cannot support the full DoD logon banner due to character limitations, the following text can be used:



""I've read & consent to terms in IS user agreem't.""
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-001384

The information system, for publicly accessible systems, displays system use information organization-defined conditions before granting further access.

NIST SP 800-53 :: AC-8 c

NIST SP 800-53A :: AC-8.2 (i)

NIST SP 800-53 Revision 4 :: AC-8 c 1



CCI-001385

The information system, for publicly accessible systems, displays references, if any, to monitoring that are consistent with privacy accommodations for such systems that generally prohibit those activities.

NIST SP 800-53 :: AC-8 c

NIST SP 800-53A :: AC-8.2 (ii)

NIST SP 800-53 Revision 4 :: AC-8 c 2



CCI-001386

The information system for publicly accessible systems displays references, if any, to recording that are consistent with privacy accommodations for such systems that generally prohibit those activities.

NIST SP 800-53 :: AC-8 c

NIST SP 800-53A :: AC-8.2 (ii)

NIST SP 800-53 Revision 4 :: AC-8 c 2



CCI-001387

The information system for publicly accessible systems displays references, if any, to auditing that are consistent with privacy accommodations for such systems that generally prohibit those activities.

NIST SP 800-53 :: AC-8 c

NIST SP 800-53A :: AC-8.2 (ii)

NIST SP 800-53 Revision 4 :: AC-8 c 2



CCI-001388

The information system, for publicly accessible systems, includes a description of the authorized uses of the system.

NIST SP 800-53 :: AC-8 c

NIST SP 800-53A :: AC-8.2 (iii)

NIST SP 800-53 Revision 4 :: AC-8 c 3




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
