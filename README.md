# Start TLS #

Upgrade a regular [`net.Stream`](http://nodejs.org/api/net.html#net_class_net_socket) connection to a secure [`tls`](http://nodejs.org/api/tls.html) connection.

Based on a version by [Andris Reinman](https://github.com/andris9/rai/blob/master/lib/starttls.js), itself based on an older version by [Nathan Rajlich](https://gist.github.com/TooTallNate/848444).

## Usage ##

This library has one method and accepts either an options hash or a prepared socket as the first argument.

The `onSecure` callback is always optional and receives `null` or an error object as the first argument. The only kind of error supported so far is a verification error, which results when the certificate authority failed to verify the certificate.

### starttls(options, [onSecure]) ###

When provided an options hash, `starttls` creates a socket by passing the hash to [`net.createConnection`](http://nodejs.org/api/net.html#net_net_createconnection_options_connectionlistener), starts the connection and returns the created socket.

```javascript
var starttls = require('starttls');

starttls({
	host: 'www.example.com',
	port: 443
}, function(err) {
	if (err) {

		// Something bad happened.
		// You should log the error and bail out.
	} else {
		this.cleartext.write('garbage');
	}
});
```

Note the first argument is non-null in the following cases:

- the certificate authority authorization check failed or was negative
- the server identity check was negative

You should always check for errors before writing to the stream to avoid man-in-the-middle attacks.

### starttls(socket, [onSecure]) ###

When provided with a [`Socket`](http://nodejs.org/api/net.html#net_class_net_socket) instance, `starttls` returns a [`SecurePair`](http://nodejs.org/api/tls.html#tls_class_securepair).

```javascript
var net = require('net');
var starttls = require('starttls');

net.createConnection({
	port: 21,
	host: example.com
}, function() {
	var securePair = starttls(this);

	securePair.on('secure', function() {
		this.cleartext.write('garbage');
	});
});
```

To avoid man-in-the-middle attacks you should also check the server identity. This check is performed automatically if you pass an options hash with a `host` property to `starttls`.

```javascript
starttls(socket, function(err) {
	if (!tls.checkServerIdentity(host, this.cleartext.getPeerCertificate())) {

		// Hostname mismatch!
		// Report error and end connection...
	}
});
```

## Example ##

See [socks5-https-client](https://github.com/mattcg/socks5-https-client) for use-case.

## Tests ##

Run `make test` or `npm test` to run tests.

## License ##

Portions of this code copyright (c) 2012, Andris Reinman and copyright (c) 2011, Nathan Rajlich.

Modified and redistributed under an [MIT license](http://mattcg.mit-license.org/).
