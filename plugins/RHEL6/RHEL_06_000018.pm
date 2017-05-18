#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_06_000018
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

package RHEL_06_000018;

# Standard modules
use utf8;
use strict;
use warnings FATAL => 'all';

# SCAR modules
use SCAR;
use SCAR::Log;
use SCAR::Backup;

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
    $self->{VULN_ID} = 'V-51391';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000232';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-65601r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000018';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE} = 'A file integrity baseline must be created.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
For AIDE to be effective, an initial database of ""known-good"" information about files must be captured and it should be able to be verified against the installed files.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
To find the location of the AIDE database file, run the following command:



# grep DBDIR /etc/aide.conf



Using the defined values of the [DBDIR] and [database] variables, verify the existence of the AIDE database file:



# ls -l [DBDIR]/[database_file_name]



If there is no database file, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Run the following command to generate a new database:



# /usr/sbin/aide --init



By default, the database will be written to the file ""/var/lib/aide/aide.db.new.gz"". Storing the database, the configuration file ""/etc/aide.conf"", and the binary ""/usr/sbin/aide"" (or hashes of these files), in a secure location (such as on read-only media) provides additional assurance about their integrity. The newly-generated database can be installed as follows:



# cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz



To initiate a manual check, run the following command:



# /usr/sbin/aide --check



If this check produces any unexpected output, investigate.
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000366

The organization implements the security configuration settings.

NIST SP 800-53 :: CM-6 b

NIST SP 800-53A :: CM-6.1 (iv)

NIST SP 800-53 Revision 4 :: CM-6 b




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
