# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000018
#
# VULN ID
#   V-51391
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000232
#
# RULE ID
#   SV-65601r1_rule
#
# STIG ID
#   RHEL-06-000018
#
# RULE TITLE
#   A file integrity baseline must be created.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000018;

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
    return 'V-51391';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000232';
}

sub get_rule_id {
    return 'SV-65601r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000018';
}

sub get_rule_title {
    return 'A file integrity baseline must be created.';
}

sub get_discussion {
    return <<'DISCUSSION';
For AIDE to be effective, an initial database of ""known-good"" information about files must be captured and it should be able to be verified against the installed files.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To find the location of the AIDE database file, run the following command:



# grep DBDIR /etc/aide.conf



Using the defined values of the [DBDIR] and [database] variables, verify the existence of the AIDE database file:



# ls -l [DBDIR]/[database_file_name]



If there is no database file, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Run the following command to generate a new database:



# /usr/sbin/aide --init



By default, the database will be written to the file ""/var/lib/aide/aide.db.new.gz"". Storing the database, the configuration file ""/etc/aide.conf"", and the binary ""/usr/sbin/aide"" (or hashes of these files), in a secure location (such as on read-only media) provides additional assurance about their integrity. The newly-generated database can be installed as follows:



# cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz



To initiate a manual check, run the following command:



# /usr/sbin/aide --check



If this check produces any unexpected output, investigate.
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
