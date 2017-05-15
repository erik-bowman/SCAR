#!/usr/bin/perl
# ------------------------------------------------------------------------------
# NAME
#   rhel7.pl
#
# SYNOPSIS
#   rhel7.pl [options]
#
# DESCRIPTION
#   Security compliance and remediation toolkit for Red Hat 7
#
# OPTIONS
#   -d [--debug]    - enable full verbosity
#   -q [--quiet]    - disables all output
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

# Standard pragmas
use strict;
use warnings FATAL => 'all';

# Standard modules
use FindBin;
use File::Spec;
use Config::Tiny;
use Getopt::Long;

# SCAR modules
use SCAR;

# Development modules
#use Data::Dumper;

# ------------------------------------------------------------------------------

$| = 1;

# Globals
use vars qw($debug $quiet $show_help $help $scar);

$debug = 0;
$quiet = 0;
$show_help = 0;

# Process options
GetOptions (
    'debug|d' => \$debug,
    'quiet|q' => \$quiet,
    'help|h'  => \$show_help,
);

if ($show_help) {
    die($help);
}

if ( $debug && $quiet ) {
    die("You cannot set both -d [--debug] and -q [--quiet]");
}

# Start SCAR
$scar = SCAR->new(File::Spec->catdir("$FindBin::Bin", "..", "conf", "scar.conf"), $debug, $quiet );

# ------------------------------------------------------------------------------

__END__
