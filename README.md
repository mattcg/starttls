# Start TLS #

Upgrade a regular [`net.Stream`](http://nodejs.org/api/net.html#net_class_net_socket) connection to a secure [`tls`](http://nodejs.org/api/tls.html) connection. See [socks5-https-client](https://github.com/mattcg/socks5-https-client) for use-case.

Based on a version by [Andris Reinman](https://github.com/andris9/rai/blob/master/lib/starttls.js), itself based on an older version by [Nathan Rajlich](https://gist.github.com/TooTallNate/848444).

## Usage ##

This library returns a [`SecurePair`](http://nodejs.org/api/tls.html#tls_class_securepair) and takes a [`Socket`](http://nodejs.org/api/net.html#net_class_net_socket) and an optional callback called on the [`secure`](http://nodejs.org/api/tls.html#tls_event_secure) event of the pair.

```javascript
var net = require('net');
var starttls = require('starttls');

var socket = net.createConnection({
	port: 21,
	host: example.com
});

socket.on('connect', function() {
	var securePair = starttls(socket, function(err) {
		securePair.cleartext.write('garbage');
	});
});
```

The callback receives `null` or an error object as the first argument. The only kind of error supported so far is a verification error, which results when the certificate authority failed to verify the certificate.

To avoid man-in-the-middle attacks you should also check the server identity.

```javascript
starttls(socket, function(err) {
	if (!tls.checkServerIdentity(host, this.cleartext.getPeerCertificate())) {

		// Hostname mismatch!
		// Report error and end connection...
	}
});
```

## License ##

Portions of this code copyright (c) 2012, Andris Reinman and copyright (c) 2011, Nathan Rajlich.

Modified and redistributed under an [MIT license](https://github.com/andris9/rai/blob/master/LICENSE).
