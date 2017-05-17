#!/bin/env perl
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
# ------------------------------------------------------------------------------

# Standard modules
use strict;
use FindBin;
use File::Spec;
use Getopt::Long;
use warnings FATAL => 'all';

# SCAR modules
use SCAR;
use SCAR::Log;
use SCAR::RHEL7;
use SCAR::Backup;
use SCAR::Loader;

# Version
our $VERSION = 0.01;

# ------------------------------------------------------------------------------

__END__
