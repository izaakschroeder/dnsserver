
var 
	dns = require('./dnsserver'), 
	redis = require('redis');
//	Presto = require('presto');

var namespace = "dns";

function inet_aton(address) {
	var parts = address.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
	return parts ? parts[1] * 16777216 + parts[2] * 65536 + parts[3] * 256 + parts[4] * 1 : false;
}

function shuffle(o) {
	for(var j, x, i = o.length; i; j = parseInt(Math.random() * i), x = o[--i], o[i] = o[j], o[j] = x);
	return o;
};

function Server() {
	var self = this;
	this.class = dns.Class.IN;
	this.backend = redis.createClient();
	this.namespace = "dns";
	this.defaultTimeToLive = 3600;

	this.server = dns.createServer(function(request, response) {
		var question = request.question;
		self.records(question.type, question.name, function(members) {
			response.aa = true;
			members.map(function(input) {
				var parts = input.split(" ", 2), ttl = parts[0], data = parts[1];
				return { ttl: parseInt(ttl), data: data };
			}).map(Server.normalizeRecord.bind(undefined, question.type)).forEach(function(data) {				
				response.addRR(question.name, question.type, question.class, data.ttl, data.data)
			})
			response.end();
		})
	});

	//this.apiHandler = Presto.app();
}

Server.normalizeRecord = function(type, input) {
	var data = input.data;
	switch(type) {
	case dns.Type.A:
		var buf = new Buffer(4);
		buf.writeUInt32BE(inet_aton(data), 0);
		return { data: buf, ttl: input.ttl } ;
	
	case dns.Type.AAAA:

	
	case dns.Type.CNAME:
		return dns.normalizeDomainName(data);
	
	case dns.Type.MX:

	
	case dns.Type.TXT:
		return data;
	
	default:
	}
}

Server.prototype.run = function() {
	//this.apiHandler.run();
	this.server.bind(53);
}

Server.prototype.makeKey = function(cls, type, name) {
	return this.namespace + ":" + " " + cls + " " + type + " " + name;
}

Server.prototype.records = function(type, name, callback) {
	var key = this.makeKey(this.class, type, name);
	this.backend.smembers(key, function(err, members) {
		if (err) {
			console.log("Error!");
			callback([]);
			return;
		}
		callback(members);
	});
}

function Record(server, key, ttl, data) {
	this.server = server;
	this.key = key;
	this.ttl = ttl;
	this.data = data;
	if (typeof ttl !== "number")
		throw new TypeError("TTL must be a number!");
}

Record.prototype.add = function(callback) {
	this.server.backend.sadd(this.key, this.ttl + " " + this.data, callback || function() { });
}

Record.prototype.remove = function(callback) {
	this.server.backend.srem(this.key, this.ttl + " " + this.data, callback || function() { });
}


Server.prototype.record = function(type, name, ttl, data) {
	var key = this.makeKey(this.class, type, name);
	return new Record(this, key, ttl || this.defaultTimeToLive, data);
}

Server.prototype.A = function(address, ip, ttl) {
	return this.record(dns.Type.A, address, ttl, ip);
}

Server.prototype.CNAME = function(address, alias, ttl) {
	this.record(dns.Type.CNAME, address, ttl, alias);
}

Server.prototype.NS = function(domain) {
	this.record(dns.Type.NS, domain)
}

Server.prototype.SOA = function(domain) {
	this.record(dns.Type.SOA, domain)
}

Server.prototype.MX = function() {

}

Server.prototype.AAAA = function(address, ip, callback) {

}

Server.prototype.SRV = function() {

}

Server.prototype.TXT = function() {

}



var server = new Server();

server.A("test.izk", "127.0.0.1").add();
//server.A("test.izk", "2130706433").remove();

server.run();


