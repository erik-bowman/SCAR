package Scar::File::Lib;

# Standard Pragmas
use utf8;
use strict;
use warnings FATAL => 'all';

# Standard Modules
use Carp qw{ croak };
use English qw{ -no_matched_vars };

# Local Modules
use Scar::File;
use Scar::Commands;
use Scar::Util::Log;

#@method
#@returns Scar::File::Lib
sub new {
    my ($class) = @ARG;
    my $self = bless {}, $class;

    log_info('Building system library datastore');

    my @lib_dirs
        = qw{ /lib /lib64 /usr/lib /usr/lib64 /lib /usr/local/lib /usr/local/lib64 };

    foreach my $lib_dir (@lib_dirs) {
        log_info("Checking $lib_dir...");
        my @dir_contents = run_find("-L $lib_dir -type f");
        foreach my $content (@dir_contents) {
            chomp $content;
            $self->{$content}->{permissions}
                = get_file_permissions($content);
            $self->{$content}->{owner}
                = get_file_owner($content);
            $self->{$content}->{group}
                = get_file_group($content);
            log_debug("Added $content");
        }
    }

    log_info('Done building systetm library datastore');
    return $self;
}

1;

__END__
