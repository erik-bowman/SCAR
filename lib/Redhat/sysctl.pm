package Redhat::sysctl;

=comment

Perl Core Pragmas

=cut

use utf8;
use strict;
use warnings FATAL => 'all';

=comment

Perl Core Modules

=cut

use File::Find ();
use Carp qw{ croak };
use English qw{ -no_matched_vars };

=comment

Scar Local Modules

=cut

use Scar::Util::Log;
use Scar::Util::Backup;

=comment

Module Version

=cut

our $VERSION = 1.4.0;

=comment

sysctl configuration files array

=cut

our @configuration_files;

=comment

Module Constructor

=cut

#@method
#@returns Redhat::sysctl
sub new {
    my ($class) = @ARG;

    log_info("Initializing $class");

    my %kernel_parameters = (
        'net.ipv4.ip_forward'                        => undef,
        'net.ipv4.conf.all.accept_source_route'      => undef,
        'net.ipv4.conf.all.accept_redirects'         => undef,
        'net.ipv4.conf.all.secure_redirects'         => undef,
        'net.ipv4.conf.all.log_martians'             => undef,
        'net.ipv4.conf.default.accept_source_route'  => undef,
        'net.ipv4.conf.default.secure_redirects'     => undef,
        'net.ipv4.conf.default.accept_redirects'     => undef,
        'net.ipv4.icmp_echo_ignore_broadcasts'       => undef,
        'net.ipv4.icmp_ignore_bogus_error_responses' => undef,
        'net.ipv4.tcp_syncookies'                    => undef,
        'net.ipv4.conf.all.rp_filter'                => undef,
        'net.ipv4.conf.default.rp_filter'            => undef,
        'net.ipv6.conf.default.accept_redirects'     => undef,
        'kernel.randomize_va_space'                  => undef,
        'kernel.exec-shield'                         => undef,
        'net.ipv4.conf.default.send_redirects'       => undef,
        'net.ipv4.conf.all.send_redirects'           => undef,
    );

    foreach my $parameter ( keys %kernel_parameters ) {

        log_debug(
            "Querying sysctl for the current value of parameter $parameter");

        open my $sysctl_query, '-|', "/sbin/sysctl -n $parameter"
            or croak "Unable to execute '/sbin/sysctl': $OS_ERROR";
        {

            while ( my $result = <$sysctl_query> ) {
                chomp $result;
                $kernel_parameters{$parameter} = $result;
            }

        }
        close $sysctl_query;

        log_debug("$parameter = $kernel_parameters{$parameter}");
    }

    log_debug('Searching for sysctl configuration files');

    my @sysctl_dirs = (
        '/run/sysctl.d/',           '/etc/sysctl.d/',
        '/usr/local/lib/sysctl.d/', '/usr/lib/sysctl.d/',
        '/lib/sysctl.d/',
    );

    foreach my $sysctl_dir (@sysctl_dirs) {

        if ( -d $sysctl_dir ) {

            File::Find::find( { wanted => \&wanted }, $sysctl_dir );

        }

    }

    push @Redhat::sysctl::configuration_files, '/etc/sysctl.conf';

    my $self = bless \%kernel_parameters, $class;

    log_debug("$class initialized");

    return $self;
}

=comment

sysctl kernel parameter setter

=cut

#@method
#@returns Redhat::sysctl
sub set_parameter {
    my ( $self, $parameter, $value ) = @ARG;

    if ( not defined $parameter or not defined $value ) {
        croak 'A parameter name and value must be specified';
    }

    if ( not defined $self->{$parameter} ) {
        croak "Invalid parameter: $parameter is not tracked by this module";
    }

    log_debug(
        "Removing any existing configuration file entries for $parameter");

    foreach my $config_file (@Redhat::sysctl::configuration_files) {

        my $make_change = 0;
        my @contents;

        open my $file_handle, '<:encoding(utf8)', $config_file
            or croak
            "Unable to open file '$config_file' for reading: $OS_ERROR";
        {

            while ( my $entry = <$file_handle> ) {
                if ( $entry =~ /^$parameter/ ) {
                    $make_change = 1;
                    next;
                }
                push @contents, $entry;
            }

        }
        close $file_handle;

        if ( $make_change == 1 ) {

            log_debug("Found $parameter in $config_file, removing");

            create_backup($config_file);

            open $file_handle, '>:encoding(utf8)', $config_file
                or croak
                "Unable to open file '$config_file' for writing: $OS_ERROR";
            {

                foreach my $entry (@contents) {

                    print {$file_handle} $entry;

                }

            }
            close $file_handle;

            log_change(
                "Modified file '$config_file' removing an entry for '$parameter'"
            );

        }

    }

    log_debug("Creating new entry in '/etc/sysctl.conf' for '$parameter'");

    open my $file_handle, '>>:encoding(utf8)', '/etc/sysctl.conf'
        or croak "Could not append to file '/etc/sysctl.conf': $OS_ERROR";
    {

        print {$file_handle} "$parameter = $value\n";

    }
    close $file_handle;

    log_change(
        "Modified file '/etc/sysctl.conf' appending '$parameter = $value'");

    log_debug("Running sysctl to set $parameter to $value");

    open my $sysctl_update, '-|', "/sbin/sysctl -w $parameter=$value"
        or croak "Unable to execute '/sbin/sysctl': $OS_ERROR";
    close $sysctl_update;

    log_change(
        "Modified active kernel parameter value by executing '/sbin/sysctl -w $parameter=$value'"
    );

    open my $sysctl_query, '-|', "/sbin/sysctl -n $parameter"
        or croak "Unable to execute '/sbin/sysctl': $OS_ERROR";
    {

        while ( my $result = <$sysctl_query> ) {
            chomp $result;
            $self->{$parameter} = $result;
        }

    }
    close $sysctl_query;

    log_info("Change completed: $parameter = $value");

    return $self;
}

=comment

Configuration file search callback

=cut

sub wanted {
    if ( -f $File::Find::name and $File::Find::name =~ /\.conf$/msx ) {

        log_debug("Found: $File::Find::name");

        push @Redhat::sysctl::configuration_files, $File::Find::name;
    }

    return;
}

1;

__END__
