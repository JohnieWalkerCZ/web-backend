use v5.36;
use strict;
use warnings;
use Test::More;
use lib 'lib';
use KSI::DB;

my ($dsn, $user, $password) = KSI::DB->dsn_from_env('sqlite:////var/ksi-be/db.sqlite');
is $dsn, 'dbi:SQLite:dbname=/var/ksi-be/db.sqlite', 'maps legacy absolute SQLite URL';
ok !defined $user && !defined $password, 'SQLite has no credentials';
($dsn, $user, $password) = KSI::DB->dsn_from_env('mysql+pymysql://u:p@db.example:3307/ksi?charset=utf8mb4');
is $dsn, 'dbi:mysql:database=ksi;host=db.example;port=3307', 'maps legacy MySQL URL';
is $user, 'u', 'preserves database user';
is $password, 'p', 'preserves database password';
eval { KSI::DB->dsn_from_env('postgres://db/ksi') };
like $@, qr/Unsupported database URI/, 'rejects unsupported schemes';
done_testing;
