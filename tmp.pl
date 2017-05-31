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

use Data::Dumper;

my $in_file
    = File::Spec::Functions::catdir( 'D:', 'Documents', 'SCAR', 'SCAR',
    'tmp.csv' );
my $out_file
    = File::Spec::Functions::catdir( 'D:', 'Documents', 'SCAR', 'SCAR', 'doc',
    'Red Hat Enterprise Linux 6 Security Technical Implementation Guide.md' );

my @table;
my @columns = ['Vuln ID','Severity','Group Title','Rule ID','STIG ID','Rule Title','Discussion','IA Controls','Check Content','Fix Text','False Positives','False Negatives','Documentable','Mitigations','Potential Impact','Third Party Tools','Mitigation Control','Responsibility','Severity Override Guidance','Check Content Reference','Classification','STIG','VMS Asset Posture','CCI'];

#@type Text::CSV_PP
my $csv = Text::CSV_PP->new( { binary => 1, eol => $INPUT_RECORD_SEPARATOR, blank_is_undef => 1 } );
$csv->column_names(@columns);

open my $io, "<", $in_file or die "$in_file: $OS_ERROR";
{
    while ( my $row = $csv->getline_hr($io) ) {
        push @table, \%{$row};
    }
}
close $io;

print <<"MD";
# Red Hat Enterprise Linux 6 Security Technical Implementation Guide

__Version:__ 1

__Release:__ 15

__Benchmark Date:__ 28 Apr 2017

The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: [disa.stig_spt\@mail.mil.](mailto:disa.stig_spt\@mail.mil)


MD


while ( @table ) {
    my $row = shift @table;
    print <<"MD";

### $row->{'STIG ID'}

__Vuln ID__ $row->{'Vuln ID'}

__Severity__ $row->{'Severity'}

__Group Title__ $row->{'Group Title'}

__Rule ID__ $row->{'Rule ID'}

__STIG ID__ $row->{'STIG ID'}

__Rule Title__

`$row->{'Rule Title'}`

__Discussion__

```
$row->{'Discussion'}
```

__Check Content__

```
$row->{'Check Content'}
```

__Fix Text__

```
$row->{'Fix Text'}
```

__CCI__

```
$row->{'CCI'}
```

MD

}

__END__
