package KSI::App;

use v5.36;
use strict;
use warnings;
use parent 'Mojolicious';
use KSI::DB;
use KSI::Auth qw(check_password new_token utc_after);
use POSIX qw(strftime);
use Cwd qw(abs_path getcwd);
use File::Spec;
use Mojo::JSON ();

sub startup ($self) {
    $self->secrets([$ENV{MOJO_SECRET} // die 'Set MOJO_SECRET']);
    $self->helper(db => sub ($c) {
        state $dbh = KSI::DB->connect;
        return $dbh;
    });

    $self->hook(before_dispatch => sub ($c) {
        $c->stash(user => undef);
        return if $c->req->method eq 'OPTIONS';
        my $auth = $c->req->headers->authorization // '';
        return unless $auth =~ /^Bearer\s+(\S+)\z/i;
        my $token = $c->db->selectrow_hashref(
            'SELECT t.access_token, t.user, t.expire, u.role FROM oauth2_tokens t JOIN users u ON u.id = t.user WHERE t.access_token = ?',
            undef, $1
        ) or return;
        my $now = strftime('%Y-%m-%d %H:%M:%S', gmtime);
        return if !defined $token->{expire} || $token->{expire} lt $now;
        $c->stash(user => $token);
    });
    $self->hook(before_dispatch => sub ($c) {
        return if $c->req->method eq 'OPTIONS';
        my $year = $c->req->headers->header('Year');
        if (!defined $year) {
            ($year) = $c->db->selectrow_array('SELECT id FROM years ORDER BY id DESC LIMIT 1');
        }
        $c->stash(year => $year);
    });

    my $r = $self->routes;
    $r->post('/auth')->to(cb => sub ($c) {
        my $grant = $c->param('grant_type') // '';
        return $c->render(status => 400) unless $grant eq 'password' || $grant eq 'refresh_token';
        my $dbh = $c->db;
        $dbh->do('DELETE FROM oauth2_tokens WHERE expire < ?', undef, utc_after(-14 * 86400));
        my $user;
        my $in_tx = 0;
        if ($grant eq 'password') {
            my $username = $c->param('username') // '';
            my $password = $c->param('password') // '';
            $user = $dbh->selectrow_hashref(
                'SELECT id, password, enabled FROM users WHERE email = ?', undef, $username
            );
            return $c->render(json => {error => 'unauthorized_client'}, status => 400)
                unless $user && $password ne '';
            return $c->render(json => {error => 'account_disabled'}, status => 400)
                unless $user->{enabled};
            return $c->render(json => {error => 'unauthorized_client'}, status => 400)
                unless check_password($password, $user->{password});
        }
        else {
            my $refresh = $c->param('refresh_token') // '';
            $dbh->begin_work;
            $in_tx = 1;
            $user = $dbh->selectrow_hashref(
                'SELECT u.id FROM oauth2_tokens t JOIN users u ON u.id = t.user WHERE t.refresh_token = ?',
                undef, $refresh
            );
            unless ($user) {
                $dbh->rollback;
                return $c->render(json => {error => 'unauthorized_client'}, status => 400);
            }
            my $deleted = $dbh->do('DELETE FROM oauth2_tokens WHERE refresh_token = ?', undef, $refresh);
            unless ($deleted && $deleted == 1) {
                $dbh->rollback;
                return $c->render(json => {error => 'unauthorized_client'}, status => 400);
            }
        }
        return $c->render(status => 401) unless $user->{enabled} // 1;

        my $access = new_token();
        my $refresh = new_token();
        my $expires = utc_after(3600);
        my $granted = strftime('%Y-%m-%d %H:%M:%S', gmtime);
        eval {
            $dbh->begin_work unless $in_tx;
            $dbh->do('INSERT INTO oauth2_tokens (access_token, user, expire, refresh_token, granted) VALUES (?, ?, ?, ?, ?)',
                undef, $access, $user->{id}, $expires, $refresh, $granted);
            $dbh->do('UPDATE users SET last_logged_in = ? WHERE id = ?', undef, $granted, $user->{id});
            $dbh->commit;
            1;
        } or do {
            my $error = $@ || 'Token issue failed';
            eval { $dbh->rollback };
            die $error;
        };
        return $c->render(json => {
            access_token => $access, token_type => 'Bearer', expires_in => 3600,
            refresh_token => $refresh,
        });
    });

    $r->get('/logout')->to(cb => sub ($c) {
        return $c->rendered(204) unless $c->stash('user');
        my ($token) = ($c->req->headers->authorization // '') =~ /^Bearer\s+(\S+)\z/i;
        $c->db->do('DELETE FROM oauth2_tokens WHERE access_token = ?', undef, $token // '');
        return $c->rendered(204);
    });

    $r->any([qw(HEAD GET)], '/years')->to(cb => sub ($c) {
        my $years = _years($c);
        return $c->rendered(200) if $c->req->method eq 'HEAD';
        return $c->render(json => {years => $years});
    });
    $r->get('/years/:id')->to(cb => sub ($c) {
        my $id = $c->param('id');
        return $c->rendered(404) unless $id =~ /\A\d+\z/;
        my $years = _years($c);
        my ($year) = grep { $_->{id} == $id } @$years;
        return $c->rendered(404) unless $year;
        return $c->render(json => {year => $year});
    });
    $r->put('/years/:id')->to(cb => sub ($c) {
        return $c->rendered(400) unless _admin($c);
        my $id = $c->param('id');
        return $c->rendered(404) unless $id =~ /\A\d+\z/;
        my $body = $c->req->json;
        my $data = ref($body) eq 'HASH' ? $body->{year} : undef;
        return $c->rendered(400) unless ref($data) eq 'HASH'
            && defined $data->{index} && defined $data->{year}
            && exists $data->{sealed} && defined $data->{point_pad}
            && ref($data->{active_orgs}) eq 'ARRAY';
        my $dbh = $c->db;
        return $c->rendered(404) unless $dbh->selectrow_array('SELECT 1 FROM years WHERE id = ?', undef, $id);
        eval {
            $dbh->begin_work;
            $dbh->do('DELETE FROM active_orgs WHERE year = ?', undef, $id);
            $dbh->do('UPDATE years SET id = ?, year = ?, sealed = ?, point_pad = ? WHERE id = ?',
                undef, @$data{qw(index year sealed point_pad)}, $id);
            for my $org (@{$data->{active_orgs}}) {
                $dbh->do('INSERT INTO active_orgs (org, year) VALUES (?, ?)', undef, $org, $data->{index});
            }
            $dbh->commit;
            1;
        } or do {
            my $error = $@ || 'Year update failed';
            eval { $dbh->rollback };
            die $error;
        };
        my ($year) = grep { $_->{id} == $data->{index} } @{_years($c)};
        return $c->render(json => {year => $year});
    });
    $r->post('/years')->to(cb => sub ($c) {
        return $c->rendered(400) unless _admin($c);
        my $body = $c->req->json;
        return $c->rendered(400) unless ref($body) eq 'HASH';
        my $data = $body->{year};
        return $c->rendered(400) unless ref($data) eq 'HASH';
        my $dbh = $c->db;
        eval {
            $dbh->begin_work;
            $dbh->do('INSERT INTO years (id, year, sealed, point_pad) VALUES (?, ?, ?, ?)', undef,
                @$data{qw(index year sealed point_pad)});
            for my $org (@{$data->{active_orgs} // []}) {
                $dbh->do('INSERT INTO active_orgs (org, year) VALUES (?, ?)', undef, $org, $data->{index});
            }
            $dbh->commit;
            1;
        } or do {
            my $error = $@ || 'Year creation failed';
            eval { $dbh->rollback };
            die $error;
        };
        my ($year) = grep { $_->{id} == $data->{index} } @{_years($c)};
        return $c->render(json => {year => $year});
    });
    $r->delete('/years/:id')->to(cb => sub ($c) {
        return $c->rendered(400) unless _admin($c);
        my $id = $c->param('id');
        return $c->rendered(404) unless $id =~ /\A\d+\z/;
        my $dbh = $c->db;
        return $c->rendered(404) unless $dbh->selectrow_array('SELECT 1 FROM years WHERE id = ?', undef, $id);
        return $c->rendered(403) if $dbh->selectrow_array('SELECT 1 FROM waves WHERE year = ? LIMIT 1', undef, $id);
        $dbh->do('DELETE FROM years WHERE id = ?', undef, $id);
        return $c->render(json => {});
    });
    $r->get('/waves')->to(cb => sub ($c) {
        my $waves = _waves($c, $c->stash('year'));
        my $user = $c->stash('user') // {};
        $waves = [grep { $_->{public} || ($user->{role} // '') =~ /\A(?:admin|org|tester)\z/ } @$waves];
        return $c->render(json => {waves => $waves});
    });
    $r->get('/waves/:id')->to(cb => sub ($c) {
        my $id = $c->param('id');
        return $c->rendered(404) unless $id =~ /\A\d+\z/;
        my ($wave) = @{_waves($c, undef, $id)};
        return $c->rendered(404) unless $wave;
        return $c->render(json => {wave => $wave});
    });
    $r->post('/waves')->to(cb => sub ($c) {
        my $user = $c->stash('user') // {};
        return $c->rendered(400) unless ($user->{role} // '') eq 'admin';
        my $body = $c->req->json;
        my $data = ref($body) eq 'HASH' ? $body->{wave} : undef;
        return $c->rendered(400) unless ref($data) eq 'HASH' && defined $data->{time_published};
        my $dbh = $c->db;
        $dbh->do('INSERT INTO waves (year, `index`, caption, garant, time_published) VALUES (?, ?, ?, ?, ?)',
            undef, $c->stash('year'), @$data{qw(index caption garant time_published)});
        my $id = $dbh->last_insert_id(undef, undef, 'waves', 'id');
        my ($wave) = @{_waves($c, undef, $id)};
        return $c->render(json => {wave => $wave});
    });
    $r->put('/waves/:id')->to(cb => sub ($c) {
        my $user = $c->stash('user') // {};
        return $c->rendered(400) unless ($user->{role} // '') =~ /\A(?:admin|org)\z/;
        my $id = $c->param('id');
        return $c->rendered(404) unless $id =~ /\A\d+\z/;
        my ($wave) = @{_waves($c, undef, $id)};
        return $c->rendered(404) unless $wave;
        return $c->rendered(400) if ($user->{role} // '') ne 'admin' && $user->{user} != $wave->{garant};
        my $body = $c->req->json;
        my $data = ref($body) eq 'HASH' ? $body->{wave} : undef;
        return $c->rendered(400) unless ref($data) eq 'HASH' && exists $data->{index}
            && exists $data->{caption} && exists $data->{garant};
        $c->db->do('UPDATE waves SET `index` = ?, caption = ?, garant = ?, time_published = ? WHERE id = ?',
            undef, @$data{qw(index caption garant)}, $data->{time_published} || $wave->{time_published}, $id);
        my ($updated) = @{_waves($c, undef, $id)};
        return $c->render(json => {wave => $updated});
    });
    $r->delete('/waves/:id')->to(cb => sub ($c) {
        my $user = $c->stash('user') // {};
        return $c->rendered(400) unless ($user->{role} // '') eq 'admin';
        my $id = $c->param('id');
        return $c->rendered(404) unless $id =~ /\A\d+\z/;
        return $c->rendered(404) unless $c->db->selectrow_array('SELECT 1 FROM waves WHERE id = ?', undef, $id);
        return $c->rendered(403) if $c->db->selectrow_array('SELECT 1 FROM tasks WHERE wave = ? LIMIT 1', undef, $id);
        $c->db->do('DELETE FROM waves WHERE id = ?', undef, $id);
        return $c->render(json => {});
    });
    $r->get('/achievements')->to(cb => sub ($c) {
        my $rows = $c->db->selectall_arrayref(
            'SELECT id, title, picture, description, year FROM achievements WHERE year IS NULL OR year = ? ORDER BY id',
            {Slice => {}}, $c->stash('year') // 0);
        return $c->render(json => {achievements => [map {_achievement_json($_)} @$rows]});
    });
    $r->get('/achievements/special/successful')->to(cb => sub ($c) {
        my ($id) = $c->db->selectrow_array(
            q{SELECT value FROM config WHERE key = 'successful_participant_trophy_id'}
        );
        return $c->rendered(404) unless defined $id;
        return _get_achievement($c, $id);
    });
    $r->get('/achievements/:id')->to(cb => sub ($c) {
        return _get_achievement($c, $c->param('id'));
    });
    $r->post('/achievements')->to(cb => sub ($c) {
        return $c->rendered(400) unless _org($c);
        my $body = $c->req->json;
        my $data = ref($body) eq 'HASH' ? $body->{achievement} : undef;
        return $c->rendered(400) unless ref($data) eq 'HASH'
            && defined $data->{title} && defined $data->{picture} && exists $data->{persistent};
        my $year = $data->{persistent} ? undef : $c->stash('year');
        $c->db->do('INSERT INTO achievements (title, picture, description, year) VALUES (?, ?, ?, ?)',
            undef, @$data{qw(title picture description)}, $year);
        my $id = $c->db->last_insert_id(undef, undef, 'achievements', 'id');
        my $row = $c->db->selectrow_hashref('SELECT id, title, picture, description, year FROM achievements WHERE id = ?', undef, $id);
        return $c->render(json => {achievement => _achievement_json($row)});
    });
    $r->put('/achievements/:id')->to(cb => sub ($c) {
        return $c->rendered(400) unless _org($c);
        my $body = $c->req->json;
        my $data = ref($body) eq 'HASH' ? $body->{achievement} : undef;
        return $c->rendered(400) unless ref($data) eq 'HASH'
            && defined $data->{title} && defined $data->{picture} && exists $data->{persistent};
        my $id = $c->param('id');
        return $c->rendered(404) unless $id =~ /\A\d+\z/;
        return $c->rendered(404) unless $c->db->selectrow_array('SELECT 1 FROM achievements WHERE id = ?', undef, $id);
        my $year = $data->{persistent} ? undef : $c->stash('year');
        $c->db->do('UPDATE achievements SET title = ?, picture = ?, description = ?, year = ? WHERE id = ?',
            undef, @$data{qw(title picture description)}, $year, $id);
        return _get_achievement($c, $id);
    });
    $r->delete('/achievements/:id')->to(cb => sub ($c) {
        return $c->rendered(400) unless _admin($c);
        my $id = $c->param('id');
        return $c->rendered(404) unless $id =~ /\A\d+\z/;
        return $c->rendered(404) unless $c->db->selectrow_array('SELECT 1 FROM achievements WHERE id = ?', undef, $id);
        $c->db->do('DELETE FROM achievements WHERE id = ?', undef, $id);
        return $c->render(json => {});
    });
    $r->get('/articles')->to(cb => sub ($c) {
        my $user = $c->stash('user') // {};
        my $where = 'year = ?';
        my @bind = ($c->stash('year') // 0);
        if (($user->{role} // '') =~ /\A(?:|participant|participant_hidden)\z/) {
            $where .= ' AND published = 1';
        }
        my ($count) = $c->db->selectrow_array("SELECT COUNT(*) FROM articles WHERE $where", undef, @bind);
        my $limit = $c->param('_limit');
        my $start = $c->param('_start');
        my $paginate = defined $limit && defined $start;
        return $c->rendered(400) if $paginate && ($limit !~ /\A\d+\z/ || $start !~ /\A\d+\z/);
        my $sql = "SELECT id, title, body, time_created, picture, published, author, resource, year FROM articles WHERE $where ORDER BY time_created DESC";
        $sql .= ' LIMIT ? OFFSET ?' if $paginate;
        my @article_bind = @bind;
        push @article_bind, $limit, $start if $paginate;
        my $rows = $c->db->selectall_arrayref($sql, {Slice => {}}, @article_bind);
        my $contents = _org($c) ? [map {_content_json($_->{resource})} grep {defined $_->{resource}} @$rows] : [];
        return $c->render(json => {articles => [map {_article_json($_)} @$rows], meta => {total => 0 + $count}, contents => $contents});
    });
    $r->get('/articles/:id')->to(cb => sub ($c) {
        my $id = $c->param('id');
        return _article_error($c, 404, '404', 'Not Found', 'Článek s tímto ID neexistuje.') unless $id =~ /\A\d+\z/;
        my $row = $c->db->selectrow_hashref('SELECT id, title, body, time_created, picture, published, author, resource, year FROM articles WHERE id = ?', undef, $id);
        return _article_error($c, 404, '404', 'Not Found', 'Článek s tímto ID neexistuje.') unless $row;
        return _article_error($c, 400, '401', 'Unauthorized', 'Přístup odepřen.')
            if !$row->{published} && !_org($c);
        return $c->render(json => {article => _article_json($row),
            contents => $row->{resource} && _org($c) ? [_content_json($row->{resource})] : []});
    });
    $r->post('/articles')->to(cb => sub ($c) {
        return _article_error($c, 400, '401', 'Unauthorized', 'Přidat článek může pouze organizátor.') unless _org($c);
        my $body = $c->req->json;
        my $data = ref($body) eq 'HASH' ? $body->{article} : undef;
        return $c->rendered(400) unless ref($data) eq 'HASH'
            && defined $data->{title} && exists $data->{body}
            && exists $data->{published} && defined $data->{time_published};
        my $time = _sql_time($data->{time_published});
        return $c->rendered(400) unless defined $time;
        my $dbh = $c->db;
        $dbh->do('INSERT INTO articles (author, title, body, published, year, time_created, picture) VALUES (?, ?, ?, ?, ?, ?, ?)',
            undef, $c->stash('user')->{user}, @$data{qw(title body published)}, $c->stash('year'), $time, $data->{picture});
        my $id = $dbh->last_insert_id(undef, undef, 'articles', 'id');
        $dbh->do('UPDATE articles SET resource = ? WHERE id = ?', undef, "articles/$id", $id);
        my $row = $dbh->selectrow_hashref('SELECT id, title, body, time_created, picture, published, author, resource, year FROM articles WHERE id = ?', undef, $id);
        return $c->render(json => {article => _article_json($row)});
    });
    $r->put('/articles/:id')->to(cb => sub ($c) {
        return _article_error($c, 400, '401', 'Unauthorized', 'Upravit článek může pouze organizátor.') unless _org($c);
        my $id = $c->param('id');
        return _article_error($c, 404, '404', 'Not Found', 'Článek s tímto ID neexistuje.') unless $id =~ /\A\d+\z/;
        return _article_error($c, 404, '404', 'Not Found', 'Článek s tímto ID neexistuje.')
            unless $c->db->selectrow_array('SELECT 1 FROM articles WHERE id = ?', undef, $id);
        my $body = $c->req->json;
        my $data = ref($body) eq 'HASH' ? $body->{article} : undef;
        return $c->rendered(400) unless ref($data) eq 'HASH'
            && defined $data->{title} && exists $data->{body}
            && exists $data->{published} && defined $data->{time_published};
        my $time = _sql_time($data->{time_published});
        return $c->rendered(400) unless defined $time;
        $c->db->do('UPDATE articles SET title = ?, body = ?, published = ?, time_created = ?, picture = ? WHERE id = ?',
            undef, @$data{qw(title body published)}, $time, $data->{picture}, $id);
        my $row = $c->db->selectrow_hashref('SELECT id, title, body, time_created, picture, published, author, resource, year FROM articles WHERE id = ?', undef, $id);
        return $c->render(json => {article => _article_json($row), contents => $row->{resource} ? [_content_json($row->{resource})] : []});
    });
    $r->delete('/articles/:id')->to(cb => sub ($c) {
        return _article_error($c, 400, '401', 'Unauthorized', 'Smazat článek může pouze organizátor.') unless _org($c);
        my $id = $c->param('id');
        return _article_error($c, 404, '404', 'Not Found', 'Článek s tímto ID neexistuje.') unless $id =~ /\A\d+\z/;
        my $deleted = $c->db->do('DELETE FROM articles WHERE id = ?', undef, $id);
        return _article_error($c, 404, '404', 'Not Found', 'Článek s tímto ID neexistuje.') unless $deleted && $deleted == 1;
        return $c->render(json => {});
    });
    $r->get('/threads')->to(cb => sub ($c) {
        my $wave = $c->param('wave');
        return $c->rendered(400) if defined $wave && $wave ne '' && $wave !~ /\A\d+\z/;
        my $year = $c->stash('year') // 0;
        my $rows;
        if ($wave) {
            $rows = $c->db->selectall_arrayref(q{
                SELECT DISTINCT th.id, th.title, th.year FROM threads th
                JOIN tasks task ON task.thread = th.id
                WHERE th.public = 1 AND th.year = ? AND task.wave = ? ORDER BY th.id DESC
            }, {Slice => {}}, $year, $wave);
        }
        else {
            $rows = $c->db->selectall_arrayref(q{
                SELECT th.id, th.title, th.year FROM threads th
                LEFT JOIN tasks task ON task.thread = th.id
                WHERE th.public = 1 AND th.year = ? AND task.id IS NULL ORDER BY th.id DESC
            }, {Slice => {}}, $year);
        }
        return $c->render(json => {threads => [map {_thread_json($c, $_)} @$rows]});
    });
    $r->post('/threads')->to(cb => sub ($c) {
        my $user = $c->stash('user');
        return $c->rendered(400) unless $user;
        my ($sealed) = $c->db->selectrow_array('SELECT sealed FROM years WHERE id = ?', undef, $c->stash('year') // 0);
        return $c->render(status => 403, json => {errors => [{status => '403', title => 'Forbidden', detail => 'Ročník zapečetěn.'}]}) if $sealed;
        my $body = $c->req->json;
        my $data = ref($body) eq 'HASH' ? $body->{thread} : undef;
        return $c->rendered(400) unless ref($data) eq 'HASH' && defined $data->{title};
        return $c->render(status => 413, json => {errors => [{status => '413', title => 'Payload too large', detail => 'Název vlákna může mít maximálně 100 znaků.'}]}) if length($data->{title}) > 100;
        my $dbh = $c->db;
        $dbh->do('INSERT INTO threads (title, public, year) VALUES (?, ?, ?)', undef,
            $data->{title}, exists $data->{public} ? !!$data->{public} : 1, $c->stash('year'));
        my $id = $dbh->last_insert_id(undef, undef, 'threads', 'id');
        my $row = $dbh->selectrow_hashref('SELECT id, title, year FROM threads WHERE id = ?', undef, $id);
        return $c->render(json => {thread => _thread_json($c, $row)});
    });
    $r->get('/threads/:id')->to(cb => sub ($c) {
        my $id = $c->param('id');
        return $c->rendered(404) unless $id =~ /\A\d+\z/;
        my $row = $c->db->selectrow_hashref('SELECT id, title, year, public FROM threads WHERE id = ?', undef, $id);
        return $c->render(status => 404, json => {errors => [{status => '404', title => 'Not Found', detail => 'Toto vlákno neexistuje.'}]}) unless $row;
        return $c->render(status => 400, json => {errors => [{status => '401', title => 'Unauthorized', detail => 'Přístup k vláknu odepřen.'}]})
            unless _thread_allowed($c, $row);
        return $c->render(json => {thread => _thread_json($c, $row)});
    });
    $r->put('/threads/:id')->to(cb => sub ($c) {
        my $user = $c->stash('user');
        return $c->rendered(200) unless $user;
        my $id = $c->param('id');
        return $c->rendered(200) unless $id =~ /\A\d+\z/
            && $c->db->selectrow_array('SELECT 1 FROM threads WHERE id = ?', undef, $id);
        my $dbh = $c->db;
        my $visit = $dbh->selectrow_hashref('SELECT last_visit FROM threads_visits WHERE thread = ? AND user = ?', undef, $id, $user->{user});
        if ($visit) {
            $dbh->do('UPDATE threads_visits SET last_last_visit = last_visit, last_visit = CURRENT_TIMESTAMP WHERE thread = ? AND user = ?', undef, $id, $user->{user});
        }
        else {
            $dbh->do('INSERT INTO threads_visits (thread, user, last_visit) VALUES (?, ?, CURRENT_TIMESTAMP)', undef, $id, $user->{user});
        }
        return $c->render(json => {});
    });
    $r->get('/threadDetails/:id')->to(cb => sub ($c) {
        my $id = $c->param('id');
        return $c->rendered(400) unless $id =~ /\A\d+\z/;
        my $thread = $c->db->selectrow_hashref('SELECT id, title, year, public FROM threads WHERE id = ?', undef, $id);
        return $c->rendered(400) unless $thread && _thread_allowed($c, $thread);
        my $user = $c->stash('user');
        my $visit = $user ? $c->db->selectrow_hashref('SELECT last_visit, last_last_visit FROM threads_visits WHERE thread = ? AND user = ?', undef, $id, $user->{user}) : undef;
        my $posts = $c->db->selectall_arrayref('SELECT id, thread, author, body, published_at, parent FROM posts WHERE thread = ? ORDER BY id', {Slice => {}}, $id);
        my @root_posts = map {0 + $_->{id}} grep {!defined $_->{parent}} @$posts;
        return $c->render(json => {threadDetails => {id => 0 + $id, root_posts => \@root_posts},
            posts => [map {_post_json($_, $user, $visit, $posts)} @$posts]});
    });
    $r->get('/posts/:id')->to(cb => sub ($c) {
        return _get_post($c, $c->param('id'));
    });
    $r->put('/posts/:id')->to(cb => sub ($c) {
        my $user = $c->stash('user');
        return _get_post($c, $c->param('id')) unless $user;
        my $body = $c->req->json;
        my $data = ref($body) eq 'HASH' ? $body->{post} : undef;
        return $c->rendered(400) unless ref($data) eq 'HASH' && defined $data->{body};
        return $c->render(status => 413, json => {errors => [{status => '413', title => 'Payload too large', detail => 'Tělo příspěvku může mít maximálně 8000 znaků.'}]}) if length($data->{body}) > 8000;
        my $post = $c->db->selectrow_hashref('SELECT id, thread, author FROM posts WHERE id = ?', undef, $c->param('id'));
        return $c->rendered(404) unless $post;
        return _get_post($c, $post->{id}) unless _org($c) || $post->{author} == $user->{user};
        $c->db->do('UPDATE posts SET body = ? WHERE id = ?', undef, $data->{body}, $post->{id});
        return _get_post($c, $post->{id});
    });
    $r->delete('/posts/:id')->to(cb => sub ($c) {
        my $user = $c->stash('user');
        return $c->rendered(400) unless $user;
        my $post = $c->db->selectrow_hashref('SELECT id, author FROM posts WHERE id = ?', undef, $c->param('id'));
        return $c->rendered(404) unless $post;
        return $c->rendered(403) unless _org($c) || $post->{author} == $user->{user};
        $c->db->do('DELETE FROM posts WHERE id = ?', undef, $post->{id});
        return $c->render(json => {});
    });
}

sub _admin ($c) {
    return (($c->stash('user') // {})->{role} // '') eq 'admin';
}

sub _org ($c) {
    return (($c->stash('user') // {})->{role} // '') =~ /\A(?:admin|org)\z/;
}

sub _get_achievement ($c, $id) {
    return $c->rendered(404) unless defined $id && $id =~ /\A\d+\z/;
    my $row = $c->db->selectrow_hashref(
        'SELECT id, title, picture, description, year FROM achievements WHERE id = ?', undef, $id
    );
    return $c->rendered(404) unless $row;
    return $c->render(json => {achievement => _achievement_json($row)});
}

sub _achievement_json ($row) {
    return {id => 0 + $row->{id}, title => $row->{title}, active => Mojo::JSON->true,
        picture => $row->{picture}, description => $row->{description},
        persistent => defined $row->{year} ? Mojo::JSON->false : Mojo::JSON->true,
        year => defined $row->{year} ? 0 + $row->{year} : undef};
}

sub _article_json ($row) {
    my $published_at = $row->{time_created};
    $published_at =~ s/ /T/ if defined $published_at;
    return {id => 0 + $row->{id}, title => $row->{title}, body => $row->{body},
        time_published => $published_at, picture => $row->{picture} || 'img/box-ksi.svg',
        published => $row->{published} ? Mojo::JSON->true : Mojo::JSON->false,
        author => 0 + $row->{author}, content => $row->{resource}, year => 0 + $row->{year}};
}

sub _article_error ($c, $http_status, $status, $title, $detail) {
    return $c->render(status => $http_status,
        json => {errors => [{status => $status, title => $title, detail => $detail}]});
}

sub _sql_time ($value) {
    return unless defined $value;
    return unless $value =~ /\A(\d{4}-\d\d-\d\d)[T ](\d\d:\d\d:\d\d)(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?\z/;
    return "$1 $2";
}

sub _content_json ($path) {
    my $empty = {id => $path, files => [], dirs => []};
    my $base = abs_path($ENV{KSI_CONTENT_ROOT} // File::Spec->catdir(getcwd(), 'data', 'content'));
    return $empty unless defined $base && defined $path && $path !~ m{(?:\A/|(?:\A|/)\.\.(?:/|\z))};
    my $dir = abs_path(File::Spec->catdir($base, split m{/}, $path));
    return $empty unless defined $dir && index($dir, "$base/") == 0 && -d $dir;
    opendir my $dh, $dir or return $empty;
    my @names = grep { $_ ne '.' && $_ ne '..' } readdir $dh;
    closedir $dh;
    my (@files, @dirs);
    for my $name (@names) {
        my $child = abs_path(File::Spec->catfile($dir, $name));
        next unless defined $child && index($child, "$base/") == 0;
        push @files, $name if -f $child;
        push @dirs, $name if -d $child;
    }
    return {id => $path, files => \@files, dirs => \@dirs};
}

sub _thread_allowed ($c, $thread) {
    return 1 if $thread->{public};
    my $user = $c->stash('user') // {};
    return 1 if ($user->{role} // '') =~ /\A(?:admin|org)\z/;
    return 0 unless $user->{user};
    return $c->db->selectrow_array('SELECT 1 FROM solution_comments WHERE thread = ? AND user = ? LIMIT 1',
        undef, $thread->{id}, $user->{user}) ? 1 : 0;
}

sub _thread_json ($c, $thread) {
    my ($posts) = $c->db->selectrow_array('SELECT COUNT(*) FROM posts WHERE thread = ?', undef, $thread->{id});
    my $user = $c->stash('user');
    my $unread = $posts;
    if ($user) {
        my ($last_visit) = $c->db->selectrow_array('SELECT last_visit FROM threads_visits WHERE thread = ? AND user = ?',
            undef, $thread->{id}, $user->{user});
        if (defined $last_visit) {
            ($unread) = $c->db->selectrow_array('SELECT COUNT(*) FROM posts WHERE thread = ? AND published_at > ?',
                undef, $thread->{id}, $last_visit);
        }
    }
    return {id => 0 + $thread->{id}, title => $thread->{title}, unread => 0 + $unread,
        posts_count => 0 + $posts, details => 0 + $thread->{id}, year => 0 + $thread->{year}};
}

sub _post_json ($post, $user, $visit, $posts) {
    my @reactions = map {0 + $_->{id}} grep {defined $_->{parent} && $_->{parent} == $post->{id}} @$posts;
    my $is_new = 0;
    if ($user) {
        $is_new = !defined $visit || !defined $visit->{last_last_visit}
            || $visit->{last_last_visit} lt $post->{published_at};
    }
    my $published_at = $post->{published_at};
    $published_at =~ s/ /T/ if defined $published_at;
    return {id => 0 + $post->{id}, thread => 0 + $post->{thread}, author => 0 + $post->{author},
        body => $post->{body}, published_at => $published_at, reaction => \@reactions,
        is_new => $is_new ? Mojo::JSON->true : Mojo::JSON->false};
}

sub _get_post ($c, $id) {
    return $c->rendered(404) unless defined $id && $id =~ /\A\d+\z/;
    my $post = $c->db->selectrow_hashref('SELECT id, thread, author, body, published_at, parent FROM posts WHERE id = ?', undef, $id);
    return $c->rendered(404) unless $post;
    my $thread = $c->db->selectrow_hashref('SELECT id, public FROM threads WHERE id = ?', undef, $post->{thread});
    return $c->rendered(404) unless $thread;
    return $c->rendered(400) unless _thread_allowed($c, $thread);
    my $user = $c->stash('user');
    my $visit = $user ? $c->db->selectrow_hashref('SELECT last_visit, last_last_visit FROM threads_visits WHERE thread = ? AND user = ?', undef, $post->{thread}, $user->{user}) : undef;
    my $posts = $c->db->selectall_arrayref('SELECT id, parent FROM posts WHERE thread = ?', {Slice => {}}, $post->{thread});
    return $c->render(json => {post => _post_json($post, $user, $visit, $posts)});
}

sub _years ($c) {
    my $rows = $c->db->selectall_arrayref(q{
        SELECT y.id, y.year, y.sealed, y.point_pad,
               COALESCE(SUM(wp.points), 0) AS sum_points,
               COALESCE(SUM(wp.tasks_cnt), 0) AS tasks_cnt
        FROM years y
        LEFT JOIN waves w ON w.year = y.id
        LEFT JOIN (
            SELECT w.id, SUM(pt.points) AS points, COUNT(t.id) AS tasks_cnt
            FROM waves w
            LEFT JOIN tasks t ON t.wave = w.id
            LEFT JOIN (
                SELECT task, SUM(max_points) AS points
                FROM modules WHERE bonus = 0 GROUP BY task
            ) pt ON pt.task = t.id
            GROUP BY w.id
        ) wp ON wp.id = w.id
        GROUP BY y.id
        ORDER BY y.id
    }, {Slice => {}});
    return [map {
        +{id => 0 + $_->{id}, index => 0 + $_->{id}, year => $_->{year},
          sum_points => 0 + $_->{sum_points}, tasks_cnt => 0 + $_->{tasks_cnt},
          sealed => $_->{sealed} ? 1 : 0, point_pad => 0 + $_->{point_pad}}
    } @$rows];
}

sub _waves ($c, $year, $id = undef) {
    return [] unless defined $year || defined $id;
    my $sql = q{
        SELECT w.id, w.year, w.`index` AS wave_index, w.caption, w.garant,
               w.time_published,
               COALESCE(SUM(pt.points), 0) AS sum_points,
               COUNT(t.id) AS tasks_cnt
        FROM waves w
        LEFT JOIN tasks t ON t.wave = w.id
        LEFT JOIN (
            SELECT task, SUM(max_points) AS points
            FROM modules WHERE bonus = 0 GROUP BY task
        ) pt ON pt.task = t.id
    };
    $sql .= defined $id ? ' WHERE w.id = ?' : ' WHERE w.year = ?';
    $sql .= ' GROUP BY w.id';
    my $rows = $c->db->selectall_arrayref($sql, {Slice => {}}, defined $id ? $id : $year);
    my $now = strftime('%Y-%m-%d %H:%M:%S', localtime);
    return [map {
        my $public = ($_->{time_published} // '') lt $now ? 1 : 0;
        +{id => 0 + $_->{id}, year => 0 + $_->{year}, index => 0 + $_->{wave_index},
          caption => $_->{caption}, garant => 0 + $_->{garant},
          time_published => $_->{time_published}, public => $public,
          sum_points => 0 + $_->{sum_points}, tasks_cnt => 0 + $_->{tasks_cnt}}
    } @$rows];
}

1;
