package Scar::File::yum_conf;

# Standard Pragmas
use utf8;
use strict;
use warnings FATAL => 'all';

# Standard Modules
use Carp qw{ croak };
use English qw{ -no_matched_vars };

# Local Modules
use Scar::Config;
use Scar::Util::Log;

sub new {
    my ($class) = @ARG;
    my $self = bless {}, $class;

    log_info('Reading /etc/yum.conf');

    my $yum_config = Scar::Config->new();
    $yum_config->open_config_file( '/etc/yum.conf', 'utf8' );
    foreach my $block ( keys %{$yum_config} ) {
        foreach my $keyword ( %{ $yum_config->{$block} } ) {
            $self->{$block}->{$keyword}
                = $yum_config->{$block}->{$keyword};
        }
    }

    log_info('Done reading /etc/yum.conf');
    return $self;
}

1;
