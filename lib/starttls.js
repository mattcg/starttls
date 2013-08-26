/**
 * Original: https://gist.github.com/TooTallNate/848444
 * Adapted: https://github.com/andris9/rai/blob/master/lib/starttls.js
 *
 * @overview
 * @author Matthew Caruana Galizia <m@m.cg>
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

module.exports = startTls;
startTls.startTls = startTls; // Old API: require('starttls').startTls

function startTls(socket, onSecure) {
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

		// The callback parameter is optional.
		if (onSecure) {
			onSecure.call(securePair, verifyError);
		}
	});

	clearText._controlReleased = true;

	return securePair;
}

function forwardEvents(events, emitterSource, emitterDestination) {
	var i, l, event, handler, forwardEvent;

	forwardEvent = function() {
		this.emit.apply(this, arguments);
	};

	for (i = 0, l = events.length; i < l; i++) {
		event = events[i];
		handler = forwardEvent.bind(emitterDestination, event);

		emitterSource.on(event, handler);
	}
}

function removeEvents(events, emitterSource) {
	var i, l;

	for (i = 0, l = events.length; i < l; i++){
		emitterSource.removeAllListeners(events[i]);
	}
}

function pipe(securePair, socket) {
	var clearText, onError, onClose, events;

	events = ['timeout', 'end', 'drain'];
	clearText = securePair.cleartext;

	onError = function(err) {
		if (clearText._controlReleased) {
			clearText.emit('error', err);
		}
	};

	onClose = function() {
		socket.removeListener('error', onError);
		socket.removeListener('close', onClose);
		removeEvents(events, socket);
	};

	// Forward event emissions from the socket to the cleartext stream.
	forwardEvents(events, socket, clearText);
	socket.on('error', onError);
	socket.on('close', onClose);

	securePair.on('error', function(err) {
		onError(err);
	});

	securePair.encrypted.pipe(socket);
	socket.pipe(securePair.encrypted);

	securePair.fd = socket.fd;

	clearText.socket = socket;
	clearText.encrypted = securePair.encrypted;
	clearText.authorized = false;

	return clearText;
}
