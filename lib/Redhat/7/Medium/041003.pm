package Redhat::7::Medium::041003;

=for comment

Core Pragmas

=cut

use utf8;
use strict;
use warnings FATAL => 'all';

=for comment

Core Modules

=cut

use Carp qw{ croak };
use English qw{ -no_matched_vars };

=for comment

Local Modules

=cut

use Scar::Util::Log;

=for comment

Version

=cut

our $VERSION = 1.4.0;

=for comment

Constructor

=cut

sub new {
    my ($class) = @ARG;

    log_info("Initializing $class");

    my $self = bless { status => undef, }, $class;

    log_debug("$class initialized");

    return $self;
}

=for comment

Plugin check method

=cut

sub check {
    my ($self) = @ARG;

    return $self;
}

=for comment

Finding remediation method

=cut

sub remediate {
    my ($self) = @ARG;

    return $self->check();
}

=for comment

Plugin status getter

=cut

sub get_status {
    my ($self) = @ARG;

    return $self->{status};
}

=for comment

Plugin Vuln ID getter

=cut

sub get_vuln_id {
    return 'V-72433';
}

=for comment

Plugin Severity getter

=cut

sub get_severity {
    return 'medium';
}

=for comment

Plugin Group Title getter

=cut

sub get_group_title {
    return 'SRG-OS-000375-GPOS-00160';
}

=for comment

Plugin Rule ID getter

=cut

sub get_rule_id {
    return 'SV-87057r2_rule';
}

=for comment

Plugin STIG ID getter

=cut

sub get_stig_id {
    return 'RHEL-07-041003';
}

=for comment

Plugin Rule Title getter

=cut

sub get_rule_title {
    return
        'The operating system must implement certificate status checking for PKI authentication.';
}

=for comment

Plugin Discussion getter

=cut

sub get_discussion {
    return <<'DISCUSSION';
Using an authentication device, such as a CAC or token that is separate from the information system, ensures that even if the information system is compromised, that compromise will not affect credentials stored on the authentication device.

Multifactor solutions that require devices separate from information systems gaining access include, for example, hardware tokens providing time-based or challenge-response authenticators and smart cards such as the U.S. Government Personal Identity Verification card and the DoD Common Access Card.

A privileged account is defined as an information system account with authorizations of a privileged user.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

This requirement only applies to components where this is specific to the function of the device or has the concept of an organizational user (e.g., VPN, proxy capability). This does not apply to authentication for the purpose of configuring the device itself (management).

Requires further clarification from NIST.

Satisfies: SRG-OS-000375-GPOS-00160, SRG-OS-000375-GPOS-00161, SRG-OS-000375-GPOS-00162
DISCUSSION
}

=for comment

Plugin Check Content getter

=cut

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the operating system implements certificate status checking for PKI authentication.

Check to see if Online Certificate Status Protocol (OCSP) is enabled on the system with the following command:

# grep cert_policy /etc/pam_pkcs11/pam_pkcs11.conf

cert_policy =ca, ocsp_on, signature;
cert_policy =ca, ocsp_on, signature;
cert_policy =ca, ocsp_on, signature;

There should be at least three lines returned. All lines must match the example output; specifically that "oscp_on" must be included in the "cert_policy" line.

If "oscp_on" is present in all "cert_policy" lines, this is not a finding.
CHECK_CONTENT
}

=for comment

Plugin Fix Text getter

=cut

sub get_fix_text {
    return <<'FIX_TEXT';
Configure the operating system to do certificate status checking for PKI authentication.

Modify all of the "cert_policy" lines in "/etc/pam_pkcs11/pam_pkcs11.conf" to include "ocsp_on".
FIX_TEXT
}

=for comment

Plugin CCI getter

=cut

sub get_cci {
    return <<'CCI';
CCI-001948
The information system implements multifactor authentication for remote access to privileged accounts such that one of the factors is provided by a device separate from the system gaining access.
NIST SP 800-53 Revision 4 :: IA-2 (11)

CCI-001953
The information system accepts Personal Identity Verification (PIV) credentials.
NIST SP 800-53 Revision 4 :: IA-2 (12)

CCI-001954
The information system electronically verifies Personal Identity Verification (PIV) credentials.
NIST SP 800-53 Revision 4 :: IA-2 (12)


CCI
}

1;

=pod

=encoding UTF-8

=head1 NAME

C<Redhat::7::Medium::041003> ??? C<RHEL-07-041003> Plugin

=head1 VERSION

This documentation refers to C<Redhat::7::Medium::041003> version 1.4.0.

=head1 SYNOPSIS

    use Redhat::7::Medium::041003;

    # Create the plugin object
    my $plugin              = Redhat::7::Medium::041003->new();

    # Perform checks and remediations
    my $check_result        = $plugin->check();
    my $remediation_result  = $plugin->remediate();

    # get plugin and policy information
    my $vuln_id             = $plugin->get_vuln_id();
    my $severity            = $plugin->get_severity();
    my $group_title         = $plugin->get_group_title();
    my $rule_id             = $plugin->get_rule_id();
    my $stig_id             = $plugin->get_stig_id();
    my $rule_title          = $plugin->get_rule_title();
    my $discussion          = $plugin->get_discussion();
    my $check_content       = $plugin->get_check_content();
    my $fix_text            = $plugin->get_fix_text();
    my $cci                 = $plugin->get_cci();

=head1 DESCRIPTION

C<RHEL-07-041003> Compliance and remediation plugin

=head1 METHODS

=head2 my $plugin              = Redhat::7::Medium::041003->new();

The plugin object constructor.

=head2 my $check_result        = $plugin->check();

Performs a compliance check and returns the results.

=head2 my $remediation_result  = $plugin->remediate();

Attempts to remediate an open finding and then returns the results of a new compliance check.

=head2 my $vuln_id             = $plugin->get_vuln_id();

Returns the plugin's Vuln ID.

=head2 my $severity            = $plugin->get_severity();

Returns the plugin's Severity.

=head2 my $group_title         = $plugin->get_group_title();

Returns the plugin's Group Title.

=head2 my $rule_id             = $plugin->get_rule_id();

Returns the plugin's Rule ID.

=head2 my $stig_id             = $plugin->get_stig_id();

Returns the plugin's STIG ID.

=head2 my $rule_title          = $plugin->get_rule_title();

Returns the plugin's Rule Title.

=head2 my $discussion          = $plugin->get_discussion();

Returns the plugin's Discussion.

=head2 my $check_content       = $plugin->get_check_content();

Returns the plugin's Check Content.

=head2 my $fix_text         = $plugin->get_fix_text();

Returns the plugin's Fix Text.

=head2 my $cci                 = $plugin->get_cci();

Returns the plugin's CCI.

=head1 DEPENDENCIES

Scar v1.4.0 or newer

=head1 INCOMPATIBILITIES

Scar v1.3.9 or older

=head1 BUGS AND LIMITATIONS

There are no known bugs in this module.

Please report problems to Erik Bowman (L<erik.bowman@icsinc.com|mailto:erik.bowman@icsinc.com>)

Patches are welcome.

=head1 AUTHOR

Erik Bowman (erik.bowman@icsinc.com)

=head1 LICENCE AND COPYRIGHT

Copyright ?? 2017 Bowman, Erik J.

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the ???Software???), to deal in the Software without
restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED ???AS IS???, WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NON-INFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

=cut

