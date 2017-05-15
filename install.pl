#!/usr/bin/perl
$main::help = <<'HELP';
# ------------------------------------------------------------------------------
# NAME
#   install.pl
#
# SYNOPSIS
#   install.pl [options] args
#
# DESCRIPTION
#   Security Compliance and Remediation toolkit installation script
#
# OPTIONS
#   --base      dir     - sets the root installation directory
#   --logs      dir     - sets the log file directory
#   --bin       dir     - sets the bin file directory
#   --lib       dir     - sets the lib file directory
#   --backups   dir     - sets the backup file directory
#   --reports   dir     - sets the report file directory
#   --plugins   dir     - sets the plugin file directory
#   --templates dir     - sets the template files directory
#   --enable-healing    - enables automatic remediation in the scar configuration file
#   -d [--debug]        - enables full output
#   -q [--quiet]        - disables all output
#   -h [--help]         - displays this message
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------
HELP

# Standard pragmas
use strict;
use warnings FATAL => 'all';

# SCAR pragmas
use lib qw(lib);

# Standard modules
use FindBin;
use File::Spec;
use Getopt::Long;
use POSIX qw(uname strftime);
use File::Path qw(make_path remove_tree);

# SCAR modules
use Config::Tiny;
use File::Copy::Recursive qw(dircopy fcopy);

# Development modules
#use Data::Dumper;

# Globals
$main::defaults = {
    os => {
        type    => '',
        version => '',
    },
    healing     => { enabled => 0, },
    directories => {
        base      => "/SCAR",
        bin       => "bin",
        lib       => "lib",
        temp      => "tmp",
        logs      => "logs",
        conf      => "conf",
        backups   => "backups",
        reports   => "reports",
        plugins   => "plugins",
        templates => "templates",
    },
};
$main::rhel = {
    directories => {
        plugins   => "plugins/RHEL",
        templates => "templates/RHEL",
    }
};
$main::rhel6 = {
    directories => {
        plugins   => "lib/RHEL6",
        templates => "templates/RHEL6",
    },
};
$main::rhel7 = {
    directories => {
        plugins   => "lib/RHEL7",
        templates => "templates/RHEL7",
    },
};

$main::scar_config    = Config::Tiny->new;
$main::os_main_config = Config::Tiny->new;
$main::os_sub_config  = Config::Tiny->new;

$main::show_help = 0;
$main::debug     = 0;
$main::quiet     = 0;

@main::install_log = ();

# Process options
GetOptions(
    'base=s'         => \$main::defaults->{directories}->{base},
    'logs=s'         => \$main::defaults->{directories}->{logs},
    'bin=s'          => \$main::defaults->{directories}->{bin},
    'lib=s'          => \$main::defaults->{directories}->{lib},
    'backups=s'      => \$main::defaults->{directories}->{backups},
    'reports=s'      => \$main::defaults->{directories}->{reports},
    'plugins=s'      => \$main::defaults->{directories}->{plugins},
    'templates=s'    => \$main::defaults->{directories}->{templates},
    'enable-healing' => \$main::defaults->{healing}->{enabled},
    'debug|d'        => \$main::debug,
    'quiet|q'        => \$main::quiet,
    'help|h'         => \$main::show_help,
);

if ($main::show_help) {
    die($main::help);
}

if ( $main::debug && $main::quiet ) {
    die("You cannot set both -d [--debug] and -q [--quiet]");
}

&install();

# ------------------------------------------------------------------------------
# SYNOPSIS
#   &install();
#
# DESCRIPTION
#   Performs all the installation steps
#
# ------------------------------------------------------------------------------

sub install {
    my ( $sysname, $nodename, $release, $version, $machine ) = POSIX::uname();
    &INFO("Starting the SCAR installation");
    die("The base directory must be an absolute path\n")
        unless $main::defaults->{directories}->{base} =~ /^\//;
    if ( $release =~ /\.el\d\.x86_64$/ ) {
        $main::defaults->{os}->{type} = 'RHEL';
        &build( $main::rhel, $main::os_main_config );
    }
    if ( $release =~ /\.el6\.x86_64$/ ) {
        $main::defaults->{os}->{version} = 6;
        &build( $main::rhel6, $main::os_sub_config );
    }
    if ( $release =~ /\.el7\.x86_64$/ ) {
        $main::defaults->{os}->{version} = 7;
        &build( $main::rhel7, $main::os_sub_config );
    }
    &build( $main::defaults, $main::scar_config );
    &INFO("Installing SCAR files");
    install_files();
    &INFO("Writing the configuration files");
    $main::scar_config->write(
        "$main::defaults->{directories}->{conf}/scar.conf", 'utf8' );
    $main::os_main_config->write(
        "$main::defaults->{directories}->{conf}/$main::defaults->{os}->{type}.conf",
        'utf8'
    );
    $main::os_sub_config->write(
        "$main::defaults->{directories}->{conf}/$main::defaults->{os}->{type}$main::defaults->{os}->{version}.conf",
        'utf8'
    );
    &INFO("Done!");
    &write_install_log();
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   &build($type, $config);
#
# DESCRIPTION
#   Populates a configuration object from a hash
#
# ARGUMENTS
#   $type       - the type of configuration to populate
#   $config     - the configuration to be populated
#
# ------------------------------------------------------------------------------

sub build {
    my ( $type, $config ) = @_;
    foreach my $block ( keys $type ) {
        foreach my $option ( keys $type->{$block} ) {
            if ( $block eq 'directories' ) {
                unless ( $type->{$block}->{$option} =~ /^\// ) {
                    $type->{$block}->{$option}
                        = File::Spec->catdir(
                        $main::defaults->{directories}->{base},
                        $type->{$block}->{$option} );
                }
                &DEBUG("Creating directory: $type->{$block}->{$option}");
                make_path( $type->{$block}->{$option} );
            }
            $config->{$block}->{$option} = $type->{$block}->{$option};
        }
    }
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   &install_files();
#
# DESCRIPTION
#   Installs all the SCAR files into their destination directories
#
# ------------------------------------------------------------------------------

sub install_files {

    &DEBUG("Cleaning up any previous installations");
    if ( -d $main::defaults->{directories}->{plugins} ) {
        &DEBUG("Deleting $main::defaults->{directories}->{plugins}");
        remove_tree( $main::defaults->{directories}->{plugins} );
    }

    if ( -d $main::defaults->{directories}->{templates} ) {
        &DEBUG("Deleting $main::defaults->{directories}->{templates}");
        remove_tree( $main::defaults->{directories}->{templates} );
    }

    if ( -d $main::defaults->{directories}->{bin} ) {
        &DEBUG("Deleting $main::defaults->{directories}->{bin}");
        remove_tree( $main::defaults->{directories}->{bin} );
    }

    &DEBUG("Installing libraries to: $INC[1]");
    dircopy( "$FindBin::Bin/lib", $INC[1] );

    &DEBUG(
        "Installing plugins to: $main::defaults->{directories}->{plugins}");
    dircopy( "$FindBin::Bin/plugins", $main::defaults->{directories}->{lib} );

    &DEBUG(
        "Installing templates to: $main::defaults->{directories}->{templates}"
    );
    dircopy( "$FindBin::Bin/templates",
        $main::defaults->{directories}->{templates} );

    &DEBUG("Installing scripts to: $main::defaults->{directories}->{bin}");
    dircopy( "$FindBin::Bin/bin", "$main::defaults->{directories}->{bin}" );
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   &write_install_log();
#
# DESCRIPTION
#   Writes the installation logs to disk
#
# ------------------------------------------------------------------------------

sub write_install_log {
    my $filename = "$main::defaults->{directories}->{logs}/install.log";
    open( my $fh, '>', $filename )
        or die "Could not open file '$filename' $!\n";
    foreach my $line (@main::install_log) {
        print $fh $line;
    }
    close $fh;
    &INFO(
        "To review the installation use $main::defaults->{directories}->{logs}/install.log"
    );
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   $result = &timestamp();
#
# DESCRIPTION
#   Returns two timestamps, YYYY-MM-DD and HH:MM:SS, in an array
#
# ------------------------------------------------------------------------------

sub timestamp {
    my $YYYYMMDD = strftime '%Y-%m-%d', gmtime();
    my $HHMMSS   = strftime '%H-%M-%S', gmtime();
    return ( $YYYYMMDD, $HHMMSS );
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   &INFO($message);
#
# DESCRIPTION
#   Prints an informational message to the user and adds it to the install log
#
# ARGUMENTS
#   $message    - the message to print and log
#
# ------------------------------------------------------------------------------

sub INFO {
    my ($message) = @_;
    my @timestamp = &timestamp();
    $message = "$timestamp[0] $timestamp[1]  INFO: $message\n";
    push @main::install_log, $message;
    return 0 if $main::quiet;
    print $message;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   &DEBUG($message);
#
# DESCRIPTION
#   Prints a debug message to the user and adds it to the install log
#
# ARGUMENTS
#   $message    - the message to print and log
#
# ------------------------------------------------------------------------------

sub DEBUG {
    my ($message) = @_;
    my @timestamp = &timestamp();
    $message = "$timestamp[0] $timestamp[1] DEBUG: $message\n";
    push @main::install_log, $message;
    return 0 unless $main::debug;
    print $message;
}

# ------------------------------------------------------------------------------

__END__
