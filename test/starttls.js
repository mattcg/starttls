/**
 * @overview
 * @author Matthew Caruana Galizia <m@m.cg>
 * @copyright Copyright (c) 2013, Matthew Caruana Galizia
 * @license MIT
 * @preserve
 */

'use strict';

/*jshint node:true*/

var assert = require('assert');
var net = require('net');
var tls = require('tls');

var starttls = require('../lib/starttls');

suite('starttls tests', function() {
	var socket, host = 'www.google.com', port = 443;

	setup(function() {
		socket = net.createConnection({
			port: port,
			host: host
		});
	});

	test('simple connect test', function(done) {
		socket.on('connect', function() {
			var pair;

			pair = starttls(socket, function(err) {
				assert.ifError(err);
				assert(pair.cleartext.authorized);
				assert.ifError(pair.cleartext.authorizationError);

				//pair.cleartext.write();
				done();
			});
		});
	});

	test('identity check test', function(done) {
		socket.on('connect', function() {
			var pair;

			pair = starttls(socket, function(err) {
				var cert;

				cert = pair.cleartext.getPeerCertificate();

				assert.equal(tls.checkServerIdentity(host, cert), true);
				assert.equal(tls.checkServerIdentity('www.facebook.com', cert), false);

				done();
			});
		});
	});
});
