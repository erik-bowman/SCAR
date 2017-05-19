# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::030010
#
# VULN ID
#   V-72081
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000046-GPOS-00022
#
# RULE ID
#   SV-86705r1_rule
#
# STIG ID
#   RHEL-07-030010
#
# RULE TITLE
#   The operating system must shut down upon audit processing failure, unless availability is an overriding concern. If availability is a concern, the system must alert the designated staff (System Administrator [SA] and Information System Security Officer [ISSO] at a minimum) in the event of an audit processing failure.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::030010;

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
    $self->{VULN_ID} = 'V-72081';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000046-GPOS-00022';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-86705r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-030010';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The operating system must shut down upon audit processing failure, unless availability is an overriding concern. If availability is a concern, the system must alert the designated staff (System Administrator [SA] and Information System Security Officer [ISSO] at a minimum) in the event of an audit processing failure.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability, and system operation may be adversely affected.



Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded.



This requirement applies to each audit data storage repository (i.e., distinct information system component where audit records are stored), the centralized audit storage capacity of organizations (i.e., all audit data storage repositories combined), or both.



Satisfies: SRG-OS-000046-GPOS-00022, SRG-OS-000047-GPOS-00023
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Confirm the audit configuration regarding how auditing processing failures are handled.



Check to see what level ""auditctl"" is set to with following command:



# auditctl -l | grep /-f

 -f 2



If the value of ""-f"" is set to ""2"", the system is configured to panic (shut down) in the event of an auditing failure.



If the value of ""-f"" is set to ""1"", the system is configured to only send information to the kernel log regarding the failure.



If the ""-f"" flag is not set, this is a CAT I finding.



If the ""-f"" flag is set to any value other than ""1"" or ""2"", this is a CAT II finding.



If the ""-f"" flag is set to ""1"" but the availability concern is not documented or there is no monitoring of the kernel log, this is a CAT III finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Configure the operating system to shut down in the event of an audit processing failure.



Add or correct the option to shut down the operating system with the following command:



# auditctl -f 2



If availability has been determined to be more important, and this decision is documented with the ISSO, configure the operating system to notify system administration staff and ISSO staff in the event of an audit processing failure with the following command:



# auditctl -f 1



Kernel log monitoring must also be configured to properly alert designated staff.



The audit daemon must be restarted for the changes to take effect.
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000139

The information system alerts designated organization-defined personnel or roles in the event of an audit processing failure.

NIST SP 800-53 :: AU-5 a

NIST SP 800-53A :: AU-5.1 (ii)

NIST SP 800-53 Revision 4 :: AU-5 a




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
