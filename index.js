'use strict';

var net = require('net');

/**
 * Forwarded instance.
 *
 * @param {String} ip The IP address.
 * @param {Number} port The port number.
 * @param {Boolean} secured The connection was secured.
 * @api private
 */
function Forwarded(ip, port, secured) {
  this.ip = ip || '127.0.0.1';
  this.secure = !!secured;
  this.port = +port || 0;
}

/**
 * List of possible proxy headers that should be checked for the original client
 * IP address and forwarded port.
 *
 * @type {Array}
 * @private
 */
var proxies = [
  {
    ip: 'x-forwarded-for',
    port: 'x-forwarded-port',
    proto: 'x-forwarded-proto'
  }, {
    ip: 'z-forwarded-for',
    port: 'z-forwarded-port',   // Estimated guess, no standard header available.
    proto: 'z-forwarded-proto'  // Estimated guess, no standard header available.
  }, {
    ip: 'forwarded',
    port: 'forwarded-port',
    proto: 'forwarded-proto'    // Estimated guess, no standard header available.
  }, {
    ip: 'x-real-ip',
    port: 'x-real-port'         // Estimated guess, no standard header available.
  }
];

/**
 * Search the headers for a possible match against a known proxy header.
 *
 * @param {Object} headers The received HTTP headers.
 * @param {Array} whitelist White list of proxies that should be checked.
 * @returns {String|Undefined} A IP address or nothing.
 * @api private
 */
function forwarded(headers) {
  for (var i = 0, length = proxies.length; i < length; i++) {
    if (!(proxies[i].ip in headers)) continue;

    var ports = (headers[proxies[i].port] || '').split(',')
      , ips = (headers[proxies[i].ip] || '').split(',');

    //
    // As these headers can potentially be set by a 1337H4X0R we need to ensure
    // that all supplied values are valid IP addresses. If we receive a none
    // IP value inside the IP header field we are going to assume that this
    // header has been compromised and should be ignored
    //
    if (!ips.length || !ips.every(net.isIP)) return;

    //
    // We've gotten a match on a HTTP header, we need to parse it further as it
    // could consist of multiple hops. The pattern for multiple hops is:
    //
    //   client, proxy, proxy, proxy, etc.
    //
    // So extracting the first IP should be sufficient.
    //
    return new Forwarded(ips.shift(), ports.shift());
  }
}

/**
 * Parse out the address information..
 *
 * @param {Object} obj A socket like object that could contain a `remoteAddress`.
 * @param {Object} headers The received HTTP headers.
 * @param {Array} whitelist White list
 * @returns {String} The IP address.
 * @api private
 */
module.exports = function parse(obj, headers, whitelist) {
  var proxied = forwarded(headers, whitelist)
    , connection = obj.connection
    , socket = connection
      ? connection.socket
      : obj.socket;

  //
  // We should always be testing for HTTP headers as remoteAddress would point
  // to proxies.
  //
  if (proxied) {
    return proxied;
  }

  // Check for the property on our given object.
  if ('object' === typeof obj) {
    if ('remoteAddress' in obj) {
      return new Forwarded(
        obj.remoteAddress,
        obj.remotePort
      );
    }

    // Edge case for Socket.IO and SockJS.
    if ('address' in obj && 'port' in obj) {
      return new Forwarded(
        obj.address,
        obj.port
      );
    }
  }

  if ('object' === typeof connection && 'remoteAddress' in connection) {
    return new Forwarded(
      connection.remoteAddress,
      connection.remotePort
    );
  }

  if ('object' === typeof socket && 'remoteAddress' in socket) {
    return new Forwarded(
      socket.remoteAddress,
      socket.remoteAddress
    );
  }

  return new Forwarded();
};
