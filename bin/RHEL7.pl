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

# Scar modules
use Redhat::7;
use Scar::Util::Log;
use Scar::Util::Backup;

# Version
our $VERSION = 0.01;

__END__
