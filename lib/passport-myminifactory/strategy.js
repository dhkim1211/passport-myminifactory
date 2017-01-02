var util = require('util')
    , OAuth2Strategy = require('passport-oauth2');

function Strategy(options, verify) {
    options = options || {};
    options.authorizationURL = options.authorizationURL || 'https://auth.myminifactory.com/web/authorize';
    options.tokenURL = options.tokenURL || 'https://auth.myminifactory.com/v1/oauth/tokens';

    OAuth2Strategy.call(this, options, verify);
    this.name = 'myminifactory';
}

util.inherits(Strategy, OAuth2Strategy);

Strategy.prototype.userProfile = function(accessToken, done) {
    this._oauth2.get('https://auth.myminifactory.com/v1/oauth/introspect', accessToken, function (err, body, res) {
        if (err) { return done(new InternalOAuthError('failed to fetch user profile', err)); }

        try {
            var json = JSON.parse(body);

            var profile = { provider: 'myminifactory' };
            profile.id = json.id;
            profile.name = json.username;
            profile.email = json.username;

            profile._raw = body;
            profile._json = json;
        } catch(e) {
            done(e);
            return;
        }
        done(null, profile);
    });
}

module.exports = Strategy;