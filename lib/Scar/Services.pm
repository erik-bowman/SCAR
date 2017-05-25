package Scar::Services;

# Standard Pragmas
use utf8;
use strict;
use warnings FATAL => 'all';

# Standard Modules
use FindBin;
use Carp qw( croak );
use English qw{ -no_matches_vars };

# Local Modules
use Scar::Commands;
use Scar::Util::Log;

#@method
#@returns Scar::Services
sub new {
    my ($class) = @ARG;
    my $self = bless {}, $class;

    log_info('Building system services datastore');

    my @chkconfig_entries = run_chkconfig('--list');

    foreach my $chkconfig_entry (@chkconfig_entries) {
        my @entry_properties = split /[:\s]+/msx, $chkconfig_entry;
        my $service_name = shift @entry_properties;

        while (@entry_properties) {
            my $runlevel_property = shift @entry_properties;
            my $runlevel_value    = shift @entry_properties;
            $self->{$service_name}->{$runlevel_property} = $runlevel_value;
        }

        $self->{$service_name}->{status}
            = run_service("$service_name status");

        log_debug("Added $service_name");
    }

    log_info('Done building system services datastore');
    return $self;
}

1;

__END__
