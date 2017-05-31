#!/usr/bin/perl

# Core Pragmas
use utf8;
use strict;
use warnings FATAL => 'all';

# Core Modules
use Carp qw{ croak };
use File::Spec::Functions;
use English qw{ -no_matched_vars };

# CPAN Modules
use Text::CSV_PP;

my $in_file
    = File::Spec::Functions::catdir( 'D:', 'Documents', 'SCAR', 'SCAR',
    'tmp.csv' );

my @table;
my @columns = [
    'Vuln ID',
    'Severity',
    'Group Title',
    'Rule ID',
    'STIG ID',
    'Rule Title',
    'Discussion',
    'IA Controls',
    'Check Content',
    'Fix Text',
    'False Positives',
    'False Negatives',
    'Documentable',
    'Mitigations',
    'Potential Impact',
    'Third Party Tools',
    'Mitigation Control',
    'Responsibility',
    'Severity Override Guidance',
    'Check Content Reference',
    'Classification',
    'STIG',
    'VMS Asset Posture',
    'CCI'
];

#@type Text::CSV_PP
my $csv = Text::CSV_PP->new(
    { binary => 1, eol => $INPUT_RECORD_SEPARATOR, blank_is_undef => 1 } );
$csv->column_names(@columns);

open my $io, "<", $in_file or die "$in_file: $OS_ERROR";
{
    while ( my $row = $csv->getline_hr($io) ) {
        push @table, \%{$row};
    }
}
close $io;

while (@table) {
    my $row = shift @table;

    if ( $row->{'STIG ID'} =~ /RHEL-07-(\d+)/msx ) {

        my $package_name
            = 'Redhat::7::' . ucfirst $row->{'Severity'} . '::' . $1;
        my $package_file
            = File::Spec::Functions::catdir( 'D:', 'Documents', 'SCAR',
            'SCAR', 'lib', 'Redhat', '7', ucfirst $row->{'Severity'},
            $1 . '.pm' );

        my $SRC = <<"SRC";
package $package_name;

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

our \$VERSION = 1.4.0;

=for comment

Constructor

=cut

sub new {
    my (\$class) = \@ARG;

    log_info("Initializing \$class");

    my \$self = bless { status => undef, }, \$class;

    log_debug("\$class initialized");

    return \$self;
}

=for comment

Plugin check method

=cut

sub check {
    my (\$self) = \@ARG;

    return \$self;
}

=for comment

Finding remediation method

=cut

sub remediate {
    my (\$self) = \@ARG;

    return \$self->check();
}

=for comment

Plugin status getter

=cut

sub get_status {
    my (\$self) = \@ARG;

    return \$self->{status};
}

=for comment

Plugin Vuln ID getter

=cut

sub get_vuln_id {
    return '$row->{'Vuln ID'}';
}

=for comment

Plugin Severity getter

=cut

sub get_severity {
    return '$row->{'Severity'}';
}

=for comment

Plugin Group Title getter

=cut

sub get_group_title {
    return '$row->{'Group Title'}';
}

=for comment

Plugin Rule ID getter

=cut

sub get_rule_id {
    return '$row->{'Rule ID'}';
}

=for comment

Plugin STIG ID getter

=cut

sub get_stig_id {
    return '$row->{'STIG ID'}';
}

=for comment

Plugin Rule Title getter

=cut

sub get_rule_title {
    return
        '$row->{'Rule Title'}';
}

=for comment

Plugin Discussion getter

=cut

sub get_discussion {
    return <<'DISCUSSION';
$row->{'Discussion'}
DISCUSSION
}

=for comment

Plugin Check Content getter

=cut

sub get_check_content {
    return <<'CHECK_CONTENT';
$row->{'Check Content'}
CHECK_CONTENT
}

=for comment

Plugin Fix Text getter

=cut

sub get_fix_text {
    return <<'FIX_TEXT';
$row->{'Fix Text'}
FIX_TEXT
}

=for comment

Plugin CCI getter

=cut

sub get_cci {
    return <<'CCI';
$row->{'CCI'}
CCI
}

1;

=pod

=encoding UTF-8

=head1 NAME

C<$package_name> – C<$row->{'STIG ID'}> Plugin

=head1 VERSION

This documentation refers to C<$package_name> version 1.4.0.

=head1 SYNOPSIS

    use $package_name;

    # Create the plugin object
    my \$plugin              = $package_name->new();

    # Perform checks and remediations
    my \$check_result        = \$plugin->check();
    my \$remediation_result  = \$plugin->remediate();

    # get plugin and policy information
    my \$vuln_id             = \$plugin->get_vuln_id();
    my \$severity            = \$plugin->get_severity();
    my \$group_title         = \$plugin->get_group_title();
    my \$rule_id             = \$plugin->get_rule_id();
    my \$stig_id             = \$plugin->get_stig_id();
    my \$rule_title          = \$plugin->get_rule_title();
    my \$discussion          = \$plugin->get_discussion();
    my \$check_content       = \$plugin->get_check_content();
    my \$fix_text            = \$plugin->get_fix_text();
    my \$cci                 = \$plugin->get_cci();

=head1 DESCRIPTION

C<$row->{'STIG ID'}> Compliance and remediation plugin

=head1 METHODS

=head2 my \$plugin              = $package_name->new();

The plugin object constructor.

=head2 my \$check_result        = \$plugin->check();

Performs a compliance check and returns the results.

=head2 my \$remediation_result  = \$plugin->remediate();

Attempts to remediate an open finding and then returns the results of a new compliance check.

=head2 my \$vuln_id             = \$plugin->get_vuln_id();

Returns the plugin's Vuln ID.

=head2 my \$severity            = \$plugin->get_severity();

Returns the plugin's Severity.

=head2 my \$group_title         = \$plugin->get_group_title();

Returns the plugin's Group Title.

=head2 my \$rule_id             = \$plugin->get_rule_id();

Returns the plugin's Rule ID.

=head2 my \$stig_id             = \$plugin->get_stig_id();

Returns the plugin's STIG ID.

=head2 my \$rule_title          = \$plugin->get_rule_title();

Returns the plugin's Rule Title.

=head2 my \$discussion          = \$plugin->get_discussion();

Returns the plugin's Discussion.

=head2 my \$check_content       = \$plugin->get_check_content();

Returns the plugin's Check Content.

=head2 my \$fix_text         = \$plugin->get_fix_text();

Returns the plugin's Fix Text.

=head2 my \$cci                 = \$plugin->get_cci();

Returns the plugin's CCI.

=head1 DEPENDENCIES

Scar v1.4.0 or newer

=head1 INCOMPATIBILITIES

Scar v1.3.9 or older

=head1 BUGS AND LIMITATIONS

There are no known bugs in this module.

Please report problems to Erik Bowman (L<erik.bowman\@icsinc.com|mailto:erik.bowman\@icsinc.com>)

Patches are welcome.

=head1 AUTHOR

Erik Bowman (erik.bowman\@icsinc.com)

=head1 LICENCE AND COPYRIGHT

Copyright © 2017 Bowman, Erik J.

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documentation
files (the “Software”), to deal in the Software without
restriction, including without limitation the rights to use,
copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NON-INFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

=cut


SRC

        my $argv = <<'RC';
--profile=.perltidyrc
RC

        open my $fh, '>:encoding(utf8)', $package_file."tmp"
            or croak "$package_file: $OS_ERROR\n";
        {
            print {$fh} $SRC;
        }
        close $fh;

        print "Wrote $package_file tmp. running tidy\n";
        system "perltidy --profile=.perltidyrc ".$package_file."tmp >$package_file";

        unlink $package_file."tmp";

    }
}

__END__
