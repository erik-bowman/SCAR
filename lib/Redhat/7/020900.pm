# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::020900
#
# VULN ID
#   V-72039
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86663r1_rule
#
# STIG ID
#   RHEL-07-020900
#
# RULE TITLE
#   All system device files must be correctly labeled to prevent unauthorized modification.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::020900;

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
    return 'V-72039';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000480-GPOS-00227';
}

sub get_rule_id {
    return 'SV-86663r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-020900';
}

sub get_rule_title {
    return
        'All system device files must be correctly labeled to prevent unauthorized modification.';
}

sub get_discussion {
    return <<'DISCUSSION';
If an unauthorized or modified device is allowed to exist on the system, there is the possibility the system may perform unintended or unauthorized operations.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify that all system device files are correctly labeled to prevent unauthorized modification.



List all device files on the system that are incorrectly labeled with the following commands:



Note: Device files are normally found under ""/dev"", but applications may place device files in other directories and may necessitate a search of the entire system.



#find /dev -context *:device_t:* \( -type c -o -type b \) -printf ""%p %Z\n""



#find /dev -context *:unlabeled_t:* \( -type c -o -type b \) -printf ""%p %Z\n""



Note: There are device files, such as ""/dev/vmci"", that are used when the operating system is a host virtual machine. They will not be owned by a user on the system and require the ""device_t"" label to operate. These device files are not a finding.



If there is output from either of these commands, other than already noted, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Run the following command to determine which package owns the device file:



# rpm -qf <filename>



The package can be reinstalled from a yum repository using the command:



# sudo yum reinstall <packagename>



Alternatively, the package can be reinstalled from trusted media using the command:



# sudo rpm -Uvh <packagename>
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000318

The organization audits and reviews activities associated with configuration controlled changes to the system.

NIST SP 800-53 :: CM-3 e

NIST SP 800-53A :: CM-3.1 (v)

NIST SP 800-53 Revision 4 :: CM-3 f



CCI-000368

The organization documents any deviations from the established configuration settings for organization-defined information system components based on organization-defined operational requirements.

NIST SP 800-53 :: CM-6 c

NIST SP 800-53A :: CM-6.1 (v)

NIST SP 800-53 Revision 4 :: CM-6 c



CCI-001812

The information system prohibits user installation of software without explicit privileged status.

NIST SP 800-53 Revision 4 :: CM-11 (2)



CCI-001813

The information system enforces access restrictions.

NIST SP 800-53 Revision 4 :: CM-5 (1)



CCI-001814

The Information system supports auditing of the enforcement actions.

NIST SP 800-53 Revision 4 :: CM-5 (1)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
