package Redhat::7::High::040700;

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
    return 'V-72301';
}

=for comment

Plugin Severity getter

=cut

sub get_severity {
    return 'high';
}

=for comment

Plugin Group Title getter

=cut

sub get_group_title {
    return 'SRG-OS-000480-GPOS-00227';
}

=for comment

Plugin Rule ID getter

=cut

sub get_rule_id {
    return 'SV-86925r1_rule';
}

=for comment

Plugin STIG ID getter

=cut

sub get_stig_id {
    return 'RHEL-07-040700';
}

=for comment

Plugin Rule Title getter

=cut

sub get_rule_title {
    return
        'The Trivial File Transfer Protocol (TFTP) server package must not be installed if not required for operational support.';
}

=for comment

Plugin Discussion getter

=cut

sub get_discussion {
    return <<'DISCUSSION';
If TFTP is required for operational support (such as the transmission of router configurations) its use must be documented with the Information System Security Officer (ISSO), restricted to only authorized personnel, and have access control rules established.
DISCUSSION
}

=for comment

Plugin Check Content getter

=cut

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify a TFTP server has not been installed on the system.

Check to see if a TFTP server has been installed with the following command:

# yum list installed tftp-server
tftp-server-0.49-9.el7.x86_64.rpm

If TFTP is installed and the requirement for TFTP is not documented with the ISSO, this is a finding.
CHECK_CONTENT
}

=for comment

Plugin Fix Text getter

=cut

sub get_fix_text {
    return <<'FIX_TEXT';
Remove the TFTP package from the system with the following command:

# yum remove tftp
FIX_TEXT
}

=for comment

Plugin CCI getter

=cut

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

1;

=pod

=encoding UTF-8

=head1 NAME

C<Redhat::7::High::040700> ??? C<RHEL-07-040700> Plugin

=head1 VERSION

This documentation refers to C<Redhat::7::High::040700> version 1.4.0.

=head1 SYNOPSIS

    use Redhat::7::High::040700;

    # Create the plugin object
    my $plugin              = Redhat::7::High::040700->new();

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

C<RHEL-07-040700> Compliance and remediation plugin

=head1 METHODS

=head2 my $plugin              = Redhat::7::High::040700->new();

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

