package Scar::File::fstab;

# Standard Pragmas
use utf8;
use strict;
use warnings FATAL => 'all';

# Standard Modules
use English qw{ -no_match_vars };

# Local Modules
use Scar::File;
use Scar::Util::Log;

sub new {
    my ($class) = @ARG;
    my $self = bless {}, $class;

    log_info('Reading /etc/fstab');

    my @fstab_entries = read_file( '/etc/fstab', 'utf8' );

    foreach my $fstab_entry (@fstab_entries) {
        if ( $fstab_entry =~ /^#/msx ) {
            next;
        }

        my @entry_properties = split /\s+/msx, $fstab_entry;

        my ($device_property,  $directory_property, $type_property,
            $options_property, $dump_property,      $fsck_property
        ) = @entry_properties;

        $self->{$directory_property} = {
            device  => $device_property,
            type    => $type_property,
            options => $options_property,
            dump    => $dump_property,
            fsck    => $fsck_property,
        };
    }

    log_info('Done reading /etc/fstab');
    return $self;
}

sub get_mount {
    my ( $self, $mount ) = @ARG;
    if ( defined $self->{$mount} ) {
        return $self->{$mount};
    }
    return;
}

1;

__END__
