use v5.36;
use strict;
use warnings;
use Test::More;
use lib 'lib';
use KSI::Auth qw(hash_password check_password new_token utc_after);

my $hash = hash_password('correct horse');
like $hash, qr/^\$2b\$12\$/, 'writes bcrypt hashes accepted by the Python backend';
ok check_password('correct horse', $hash), 'accepts matching password';
ok !check_password('wrong horse', $hash), 'rejects wrong password';
ok !check_password('correct horse', 'not-a-bcrypt-hash'), 'rejects malformed stored hash';
my $token = new_token();
like $token, qr/\A[A-Za-z0-9_-]{54}\z/, 'token is URL-safe and has 40 random bytes';
is length(new_token()), 54, 'token length is stable';
like utc_after(3600), qr/\A\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\z/, 'expiry is SQL datetime format';
done_testing;
