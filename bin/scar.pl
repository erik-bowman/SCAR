#!/usr/bin/perl
# ------------------------------------------------------------------------------
# NAME
#   scar.pl
#
# SYNOPSIS
#   scar.pl [options] os version
#
# DESCRIPTION
#   Security compliance and remediation toolkit
#
# OPTIONS
#   -d [--debug]    - enable full verbosity
#   -q [--quiet]    - disables all output
#
# ARGUMENTS
#   os              - the operating system type
#   version         - the operating system versiion
#
# SEE ALSO
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
# ------------------------------------------------------------------------------

# Standard pragmas
use strict;
use warnings FATAL => 'all';

# Standard modules
use Getopt::Long;
use lib qw(../lib);

# Internal modules
use SCAR;

# Development modules
use Data::Dumper;
# ------------------------------------------------------------------------------

# Globals
use vars qw($verbosity $scar);

# Process options
GetOptions (
    'debug|d' => \$verbosity,
    'quiet|q' => \$verbosity,
);
# ------------------------------------------------------------------------------

# Start SCAR
$scar = initialize();

print Dumper($scar);

__END__