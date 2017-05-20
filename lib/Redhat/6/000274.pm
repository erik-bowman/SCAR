# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000274
#
# VULN ID
#   V-38658
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000077
#
# RULE ID
#   SV-50459r4_rule
#
# STIG ID
#   RHEL-06-000274
#
# RULE TITLE
#   The system must prohibit the reuse of passwords within five iterations.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000274;

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
    return 'V-38658';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000077';
}

sub get_rule_id {
    return 'SV-50459r4_rule';
}

sub get_stig_id {
    return 'RHEL-06-000274';
}

sub get_rule_title {
    return
        'The system must prohibit the reuse of passwords within five iterations.';
}

sub get_discussion {
    return <<'DISCUSSION';
Preventing reuse of previous passwords helps ensure that a compromised password is not reused by a user.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To verify the password reuse setting is compliant, run the following command:



# grep remember /etc/pam.d/system-auth



The output must be a line beginning with ""password required pam_pwhistory.so"" and ending with ""remember=5"".



If the line is commented out, the line does not contain the specified elements, or the value for ""remember"" is less than 5, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Do not allow users to reuse recent passwords. This can be accomplished by using the ""remember"" option for the ""pam_pwhistory"" PAM module. In the file ""/etc/pam.d/system-auth"", append ""remember=5"" to the line which refers to the ""pam_pwhistory.so"" module, as shown:



password required pam_pwhistory.so [existing_options] remember=5



The DoD requirement is five passwords.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000200

The information system prohibits password reuse for the organization defined number of generations.

NIST SP 800-53 :: IA-5 (1) (e)

NIST SP 800-53A :: IA-5 (1).1 (v)

NIST SP 800-53 Revision 4 :: IA-5 (1) (e)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
