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
var starttls = require('../lib/starttls').startTls;

suite('starttls tests', function() {
	var socket;

	setup(function() {
		socket = net.createConnection({
			port: 443,
			host: 'www.example.com'
		});
	});

	test('', function(done) {
		socket.on('connect', function() {
			var pair;

			pair = starttls(socket, function() {
				assert(pair.cleartext.authorized);
				assert.ifError(pair.cleartext.authorizationError);

				//pair.cleartext.write();
				done();
			});
		});
	});
});
