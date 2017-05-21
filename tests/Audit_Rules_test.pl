#!/usr/bin/perl
use strict;
use warnings FATAL => 'all';

use FindBin;
use File::Spec::Functions;
use lib File::Spec::Functions::catdir($FindBin::Bin, qw{.. lib});

use Redhat::Audit::Rules;

use Data::Dumper;

my $auditrules = Redhat::Audit::Rules->new();

print Data::Dumper::Dumper($auditrules->load_audit_rules());
