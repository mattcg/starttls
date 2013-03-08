/**
 * Original: https://gist.github.com/TooTallNate/848444
 * Adapted: https://github.com/andris9/rai/blob/master/lib/starttls.js
 *
 * @overview
 * @author Andris Reinman <andris.reinman@gmail.com>
 * @author Nathan Rajlich <nathan@tootallnate.net>
 * @copyright Copyright (c) 2012, Andris Reinman
 * @copyright Copyright (c) 2011, Nathan Rajlich
 * @license MIT
 * @preserve
 */

'use strict';

/*jshint node:true*/

var tls = require('tls');
var crypto = require('crypto');

exports.startTls = function(socket, onSecure) {
	var credentials, securePair, clearText;

	socket.ondata = null;
	socket.removeAllListeners('data');
	credentials = crypto.createCredentials();
	securePair = tls.createSecurePair(credentials, false);

	clearText = pipe(securePair, socket);

	securePair.on('secure', function() {
		var verifyError = securePair.ssl.verifyError();

		// A cleartext stream has the boolean property 'authorized' to determine if it was verified by the CA. If 'authorized' is false, a property 'authorizationError' is set on the stream.
		if (verifyError) {
			clearText.authorized = false;
			clearText.authorizationError = verifyError;
		} else {
			clearText.authorized = true;
		}

		// The callback parameter is optional
		if (onSecure) {
			onSecure();
		}
	});

	clearText._controlReleased = true;

	return securePair;
};

function forwardEvents(events, emitterSource, emitterDestination) {
	var i, l, map = [], name, handler;
	var forwardEvent = function() {
		this.emit.apply(this, arguments);
	};

	for (i = 0, l = events.length; i < l; i++) {
		name = events[i];
		
		handler = forwardEvent.bind(emitterDestination, name);
		
		map.push(name);
		emitterSource.on(name, handler);
	}
	
	return map;
}

function removeEvents(map, emitterSource) {
	for (var i = 0, l = map.length; i < l; i++){
		emitterSource.removeAllListeners(map[i]);
	}
}

function pipe(securePair, socket) {
	var clearText, onError, onClose, eventsMap;

	securePair.encrypted.pipe(socket);
	socket.pipe(securePair.encrypted);

	securePair.fd = socket.fd;

	clearText = securePair.cleartext;

	clearText.socket = socket;
	clearText.encrypted = securePair.encrypted;
	clearText.authorized = false;

	// Forward event emissions from the socket to the clear text stream
	eventsMap = forwardEvents(['timeout', 'end', 'drain'], socket, clearText);

	onError = function(err) {
		if (clearText._controlReleased) {
			clearText.emit('error', err);
		}
	};

	onClose = function() {
		socket.removeListener('error', onError);
		socket.removeListener('close', onClose);
		removeEvents(eventsMap, socket);
	};

	socket.on('error', onError);
	socket.on('close', onClose);

	// It's possible for a SecurePair to emit an 'error' event (see SecurePair.prototype.error in tls.js in at least node v0.8.21).
	securePair.on('error', function(err) {
		clearText.emit('error', err);
	});

	return clearText;
}
