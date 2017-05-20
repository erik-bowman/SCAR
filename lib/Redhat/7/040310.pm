# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::040310
#
# VULN ID
#   V-72235
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000423-GPOS-00187
#
# RULE ID
#   SV-86859r2_rule
#
# STIG ID
#   RHEL-07-040310
#
# RULE TITLE
#   All networked systems must use SSH for confidentiality and integrity of transmitted and received information as well as information during preparation for transmission.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::040310;

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
    return 'V-72235';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000423-GPOS-00187';
}

sub get_rule_id {
    return 'SV-86859r2_rule';
}

sub get_stig_id {
    return 'RHEL-07-040310';
}

sub get_rule_title {
    return
        'All networked systems must use SSH for confidentiality and integrity of transmitted and received information as well as information during preparation for transmission.';
}

sub get_discussion {
    return <<'DISCUSSION';
Without protection of the transmitted information, confidentiality and integrity may be compromised because unprotected communications can be intercepted and either read or altered.



This requirement applies to both internal and external networks and all types of information system components from which information can be transmitted (e.g., servers, mobile devices, notebook computers, printers, copiers, scanners, and facsimile machines). Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification.



Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and vice versa.



Satisfies: SRG-OS-000423-GPOS-00187, SRG-OS-000423-GPOS-00188, SRG-OS-000423-GPOS-00189, SRG-OS-000423-GPOS-00190
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify SSH is loaded and active with the following command:



# systemctl status sshd

 sshd.service - OpenSSH server daemon

   Loaded: loaded (/usr/lib/systemd/system/sshd.service; enabled)

   Active: active (running) since Tue 2015-11-17 15:17:22 EST; 4 weeks 0 days ago

 Main PID: 1348 (sshd)

   CGroup: /system.slice/sshd.service

           ??1348 /usr/sbin/sshd -D



If ""sshd"" does not show a status of ""active"" and ""running"", this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the SSH service to automatically start after reboot with the following command:



# systemctl enable sshd ln -s '/usr/lib/systemd/system/sshd.service' '/etc/systemd/system/multi-user.target.wants/sshd.service'
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-002418

The information system protects the confidentiality and/or integrity of transmitted information.

NIST SP 800-53 Revision 4 :: SC-8



CCI-002420

The information system maintains the confidentiality and/or integrity of information during preparation for transmission.

NIST SP 800-53 Revision 4 :: SC-8 (2)



CCI-002421

The information system implements cryptographic mechanisms to prevent unauthorized disclosure of information and/or detect changes to information during transmission unless otherwise protected by organization-defined alternative physical safeguards.

NIST SP 800-53 Revision 4 :: SC-8 (1)



CCI-002422

The information system maintains the confidentiality and/or integrity of information during reception.

NIST SP 800-53 Revision 4 :: SC-8 (2)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
