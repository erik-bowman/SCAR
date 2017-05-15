#!/usr/bin/perl
# ------------------------------------------------------------------------------
# NAME
#   spinner.pl
#
# SYNOPSIS
#   spinner.pl [options] args
#
# DESCRIPTION
#
#
# OPTIONS
#
#
# ARGUMENTS
#
#
# SEE ALSO
#
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

# Standard pragmas
use strict;
use warnings FATAL => 'all';
use lib qw(lib);
use SCAR::Console;

BEGIN { @INC = grep {$_ ne '.'} @INC };

# ------------------------------------------------------------------------------

my $screen = SCAR::Console->new();
$screen->component_refresh;

__END__
