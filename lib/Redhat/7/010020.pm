# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::010020
#
# VULN ID
#   V-71855
#
# SEVERITY
#   high
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86479r2_rule
#
# STIG ID
#   RHEL-07-010020
#
# RULE TITLE
#   The cryptographic hash of system files and commands must match vendor values.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::010020;

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
    return 'V-71855';
}

sub get_severity {
    return 'high';
}

sub get_group_title {
    return 'SRG-OS-000480-GPOS-00227';
}

sub get_rule_id {
    return 'SV-86479r2_rule';
}

sub get_stig_id {
    return 'RHEL-07-010020';
}

sub get_rule_title {
    return
        'The cryptographic hash of system files and commands must match vendor values.';
}

sub get_discussion {
    return <<'DISCUSSION';
Without cryptographic integrity protections, system command and files can be altered by unauthorized users without detection.



Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the key used to generate the hash.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the cryptographic hash of system files and commands match the vendor values.



Check the cryptographic hash of system files and commands with the following command:



Note: System configuration files (indicated by a ""c"" in the second column) are expected to change over time. Unusual modifications should be investigated through the system audit log.



# rpm -Va | grep '^..5'



If there is any output from the command for system binaries, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Run the following command to determine which package owns the file:



# rpm -qf <filename>



The package can be reinstalled from a yum repository using the command:



# sudo yum reinstall <packagename>



Alternatively, the package can be reinstalled from trusted media using the command:



# sudo rpm -Uvh <packagename>
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000663

The organization (or information system) enforces explicit rules governing the installation of software by users.

NIST SP 800-53 :: SA-7

NIST SP 800-53A :: SA-7.1 (ii)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
