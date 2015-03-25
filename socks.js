var socks = require('socksv5'),
    ipbytes = require('./node_modules/socksv5/lib/utils').ipbytes,
    REP  = require('./node_modules/socksv5/lib/constants').REP,
    ATYP = require('./node_modules/socksv5/lib/constants').ATYP,
    conf_path = "conf.json",
    fs = require('fs'),
    conf = JSON.parse(fs.readFileSync(conf_path));
var authB = socks.auth.UserPassword(conf.user, conf.pass);

var srv = socks.createServer(function(info, accept, deny) {
  var protoVer = 0x05;
  if (info['auth_info'] != undefined) {
    var authInfo = info.auth_info;
    // console.log("SOCKS v5 auth info", authInfo);
  } else if (info['username'] != undefined) {
    // console.log("SOCKS v4 user name: " + info.username);
    protoVer = 0x04;
  }
  var client = socks.connect({
    host: info.dstAddr,
    port: info.dstPort,
    proxyHost: conf.host,
    proxyPort: conf.port,
    auths: [ authB ]
  }, function(dstSock) {
    accept(false, function(socket, req) {
      console.log("accept conn from " + req.srcAddr);
      var localbytes = ipbytes(dstSock.localAddress),
          len = localbytes.length;
      switch(protoVer) {
      case 0x05:
        var bufrep = new Buffer(6 + len),
            p = 4;
        bufrep[0] = protoVer;
        bufrep[1] = REP.SUCCESS;
        bufrep[2] = 0x00;
        bufrep[3] = (len === 4 ? ATYP.IPv4 : ATYP.IPv6);
        for (var i = 0; i < len; ++i, ++p)
          bufrep[p] = localbytes[i];
        bufrep.writeUInt16BE(dstSock.localPort, p, true);
        socket.write(bufrep);
      break;
      case 0x04:
        var bufrep = new Buffer(8),
            p = 4;
        var len = 4;
        bufrep[0] = 0x00;
        bufrep[1] = REP.SUCCESS_V4;
        bufrep.writeUInt16BE(dstSock.localPort, 2, true);
        for (var i = 0; i < len; ++i, ++p)
          bufrep[p] = localbytes[i];
        socket.write(bufrep);
      break;
      }
   
      socket.pipe(dstSock).pipe(socket); socket.resume(); socket.dstSock = dstSock;
    });
  }).on('error', function(err) {
    console.log('error connecting, denying');
    deny();
  });
});
srv.useAuth(socks.auth.UserPassword(function(user, password, cb) {
  cb(/*user === 'nodejs' && password === 'rules!'*/ true);
}));
srv.listen(1080, 'localhost', function() {
  console.log('SOCKS server listening on port 1080');
});

srv.useAuth(socks.auth.None());
