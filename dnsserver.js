

var 
	util = require('util'),
	Buffer = require('buffer').Buffer,
	dgram = require('dgram');

//http://en.wikipedia.org/wiki/List_of_DNS_record_types
var Type = {
	A: 1,
	AAAA: 28,
	AFSDB: 18,
	APL: 42,
	CERT: 37,
	CNAME: 5,
	DHCID: 49,
	DLV: 32769,
	DNAME: 39,
	DNSKEY: 48,
	DS: 43,
	HIP: 55,
	IPSECKEY: 45,
	KEY: 25,
	KX: 36,
	LOC: 29,
	MX: 15,
	NAPTR: 35,
	NS: 2,
	NSEC: 47,
	NSEC3: 50,
	NSEC3PARAM: 51,
	PTR: 12,
	RRSIG: 46,
	RP: 17,
	SIG: 24,
	SOA: 6,
	SPF: 99,
	SRV: 33,
	SSHFP: 44,
	TA: 32768,
	TKEY: 249,
	TSIG: 250,
	TXT: 16,

	ALL: 255,
	AXFR: 252,
	IXFR: 251,
	OPT: 41
};

var Class = {
	IN: 1,
	CH: 3,
	HS: 4,
	NONE: 254,
	ANY: 255
}

exports.Type = Type;
exports.Class = Class;

function Server(cb) {
	dgram.Socket.call(this, 'udp4');

	var self = this;
	this.on('message', function(msg, rinfo) {
		//split up the message into the dns request header info and the query
		var request = processRequest(msg, rinfo);
		var response = new Response(self, rinfo, request);
		this.emit('request', request, response);
	});

	if (cb) 
		this.addListener('request', cb);
}
util.inherits(Server, dgram.Socket);



// slices a single byte into bits
// assuming only single bytes
function sliceBits(b, off, len) {
	var s = 7 - (off + len - 1);

	b = b >>> s;
	return b & ~(0xff << len);
}

//takes a buffer as a request
function processRequest(req, rinfo) {
	//see rfc1035 for more details
	//http://tools.ietf.org/html/rfc1035#section-4.1.1

	var query = {};

	for (var k in rinfo)
		query[k] = rinfo[k];

	query.header = {};
	//TODO write code to break questions up into an array
	query.question = {};

	var tmpSlice;
	var tmpByte;

	//transaction id
	// 2 bytes
	query.header.id = req.slice(0,2);

	//slice out a byte for the next section to dice into binary.
	tmpSlice = req.slice(2,3);
	//convert the binary buf into a string and then pull the char code
	//for the byte
	tmpByte = tmpSlice.toString('binary', 0, 1).charCodeAt(0);

	//qr
	// 1 bit
	query.header.qr = sliceBits(tmpByte, 0,1);
	//opcode
	// 0 = standard, 1 = inverse, 2 = server status, 3-15 reserved
	// 4 bits
	query.header.opcode = sliceBits(tmpByte, 1,4);
	//authorative answer
	// 1 bit
	query.header.aa = sliceBits(tmpByte, 5,1);
	//truncated
	// 1 bit
	query.header.tc = sliceBits(tmpByte, 6,1);
	//recursion desired
	// 1 bit
	query.header.rd = sliceBits(tmpByte, 7,1);

	//slice out a byte to dice into binary
	tmpSlice = req.slice(3,4);
	//convert the binary buf into a string and then pull the char code
	//for the byte
	tmpByte = tmpSlice.toString('binary', 0, 1).charCodeAt(0);

	//recursion available
	// 1 bit
	query.header.ra = sliceBits(tmpByte, 0,1);

	//reserved 3 bits
	// rfc says always 0
	query.header.z = sliceBits(tmpByte, 1,3);

	//response code
	// 0 = no error, 1 = format error, 2 = server failure
	// 3 = name error, 4 = not implemented, 5 = refused
	// 6-15 reserved
	// 4 bits
	query.header.rcode = sliceBits(tmpByte, 4,4);

	//question count
	// 2 bytes
	query.header.qdcount = req.slice(4,6);
	//answer count
	// 2 bytes
	query.header.ancount = req.slice(6,8);
	//ns count
	// 2 bytes
	query.header.nscount = req.slice(8,10);
	//addition resources count
	// 2 bytes
	query.header.arcount = req.slice(10, 12);

	//assuming one question
	//qname is the sequence of domain labels
	//qname length is not fixed however it is 4
	//octets from the end of the buffer
	query.question.qname = req.slice(12, req.length - 4);
	//qtype
	query.question.qtype = req.slice(req.length - 4, req.length - 2);
	//qclass
	query.question.qclass = req.slice(req.length - 2, req.length);

	query.question.name = qnameToDomain(query.question.qname);
	query.question.type = query.question.qtype[0] * 256 + query.question.qtype[1];
	query.question.class = query.question.qclass[0] * 256 + query.question.qclass[1];

	return query;
}

function Response(socket, rinfo, query) {
	this.socket = socket;
	this.rinfo = rinfo;
	this.header = {};

	//1 byte
	this.header.id = query.header.id; //same as query id

	//combined 1 byte
	this.header.qr = 1; //this is a response
	this.header.opcode = 0; //standard for now TODO: add other types 4-bit!
	this.header.aa = 0; //authority... TODO this should be modal
	this.header.tc = 0; //truncation
	this.header.rd = 1; //recursion asked for

	//combined 1 byte
	this.header.ra = 0; //no rescursion here TODO
	this.header.z = 0; // spec says this MUST always be 0. 3bit
	this.header.rcode = 0; //TODO add error codes 4 bit.

	//1 byte
	this.header.qdcount = 1; //1 question
	//1 byte
	this.header.ancount = 0; //number of rrs returned from query
	//1 byte
	this.header.nscount = 0;
	//1 byte
	this.header.arcount = 0;

	this.question = {};
	this.question.qname = query.question.qname;
	this.question.qtype = query.question.qtype;
	this.question.qclass = query.question.qclass;

	this.rr = [];
}

Response.prototype.addRR = function(domain, qtype, qclass, ttl, rdata) {
	var r = {}, address;
	r.qname = domainToQname(domain);
	r.qtype = qtype;
	r.qclass = qclass;
	r.ttl = ttl;
	r.rdata = rdata;
	this.rr.push(r);
	this.header.ancount++;
}

Response.prototype.end = function(callback) {
	var buffer = this.toBuffer();
	this.socket.send(buffer, 0, buffer.length, this.rinfo.port, this.rinfo.address, callback || function() {});
}

Response.prototype.toBuffer = function() {
	var offset = 0;
	var qnameLen = this.question.qname.length;
	var len = 16 + qnameLen;
	var buf = new Buffer(len + this.rr.reduce(function(prev, curr) { return prev + 10 + curr.qname.length + curr.rdata.length; }, 0));

	
	this.header.id.copy(buf, offset, 0, this.header.id.length);
	offset +=2;

	buf[offset++] = 0x00 | this.header.qr << 7 | this.header.opcode << 3 | this.header.aa << 2 | this.header.tc << 1 | this.header.rd;


	buf[offset++] = 0x00 | this.header.ra << 7 | this.header.z << 4 | this.header.rcode;

	buf.writeUInt16BE(this.header.qdcount, offset);
	offset += 2;

	buf.writeUInt16BE(this.header.ancount, offset);
	offset += 2;

	buf.writeUInt16BE(this.header.nscount, offset);
	offset += 2;

	buf.writeUInt16BE(this.header.arcount, offset);
	offset += 2;

	//end header

	this.question.qname.copy(buf, offset, 0, this.question.qname.length);
	offset += this.question.qname.length;

	this.question.qtype.copy(buf, offset, 0, this.question.qtype.length);
	offset += this.question.qtype.length;

	this.question.qclass.copy(buf, offset, 0, this.question.qclass.length);
	offset += this.question.qclass.length;

	this.rr.forEach(function(rr) {
		rr.qname.copy(buf, offset);
		offset += rr.qname.length;
		
		buf.writeUInt16BE(rr.qtype, offset);
		offset += 2;

		buf.writeUInt16BE(rr.qclass, offset);
		offset += 2;
		
		buf.writeUInt32BE(rr.ttl, offset);
		offset += 4;
		
		buf.writeUInt16BE(rr.rdata.length, offset);
		offset += 2;
		
		if (rr.rdata instanceof Buffer)
			rr.rdata.copy(buf, offset)
		else
			buf.write(rr.rdata)

		offset += rr.rdata.length;
	})

	//TODO compression

	return buf;
}



function domainToQname(domain) {
	var tokens = domain.split(".");
	var len = domain.length + 2;
	var qname = new Buffer(len);
	var offset = 0;
	for (var i = 0; i < tokens.length; i++) {
		qname[offset] = tokens[i].length;
		offset++;
		for (var j = 0; j < tokens[i].length; j++) {
			qname[offset] = tokens[i].charCodeAt(j);
			offset++;
		}
	}
	qname[offset] = 0;

	return qname;
}


function qnameToDomain(qname) {
	var domain= '';
	for (var i = 0; i < qname.length; i++) {
		if (qname[i] == 0) {
			//last char chop trailing .
			domain = domain.substring(0, domain.length - 1);
			break;
		}

		var tmpBuf = qname.slice(i+1, i+qname[i]+1);
		domain += tmpBuf.toString('binary', 0, tmpBuf.length);
		domain += '.';

		i = i + qname[i];
	}

	return domain;
}

exports.Server = Server;

exports.normalizeDomainName = domainToQname;
exports.denormalizeDomainName = qnameToDomain;

exports.createServer = function(cb) {
  return new Server(cb);
}