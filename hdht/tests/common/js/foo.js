const net = require('compact-encoding-net');
const cenc = require('compact-encoding');
const NoiseHandshake = require('./noise-handshake')
const curve = require('noise-curve-ed')
const state = cenc.state();

const log = (...x) => [x[0], console.log(...x)][0]
const addr = '1:2:3::1';


net.ipv6.preencode(state, addr);

handshake = new NoiseHandshake('IK', true, null, { curve })
log(handshake);
//console.log(state);
//let buf = log(cenc.encode(net.ipv6, addr));
//log(buf.length);
//log([...buf])
//console.log(state);
//net.ipv6.encode(
