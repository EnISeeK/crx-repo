var async = require('async');
var express = require('express');
var fs = require('fs');
var http = require('http');
var mkdirp = require('mkdirp');
var multer  = require('multer');
var path = require('path');
var rimraf = require('rimraf');
var rsa = require('node-rsa');
var semver = require('semver');
var serveIndex = require('serve-index');
var streamifier = require('streamifier')
var temp = require('temp');
var unzip = require('unzip');
var xmlbuilder = require('xmlbuilder');
var ChromeExtension = require('crx');

function fileExists(filePath, cb) {
  fs.exists(filePath, function(exists) { cb(null, exists); });
}

function writeFile(filePath, fileContents, cb) {
  var dirname = path.dirname(filePath);
  async.waterfall([
    function(cb) {
      fileExists(dirname, cb);
    },
    function(exists, cb) {
      if (exists) {
        cb();
      } else {
        mkdirp(dirname, function(err) { cb(err); });
      }
    },
    function(cb) {
      fs.writeFile(filePath, fileContents, {encoding: 'utf8'}, function(err) {
        return cb(err);
      });
    },
    function(cb) {
      cb(null, fileContents);
    }
  ], cb);
}

function getPrivateKey(keyPath, cb) {
  async.waterfall([
    function(cb) {
      fileExists(keyPath, cb);
    },
    function(exists, cb) {
      if (exists) {
        fs.readFile(keyPath, cb);
      } else {
        var key = new rsa({b: 1024});
        var keyVal = key.exportKey('pkcs1-private-pem');
        writeFile(keyPath, keyVal, cb);
      }
    }
  ], cb);
}

function isDirectory(file, cb) {
  fs.stat(file, function(err, stat) {
    if (err) {
      cb(false);
    } else {
      cb(stat.isDirectory());
    }
  });
};

function findSubDirectories(dir, cb) {
  async.waterfall([
    function(cb) {
      fs.readdir(dir, cb);
    },
    function(files, cb) {
      function filterFn(file, cb) {
        isDirectory(path.join(dir, file), cb);
      };
      async.filter(files, filterFn, function(results) { cb(null, results); });
    }
  ], cb);
}


var CrxRepo = function(address, port) {
  this.dataDir = path.join(process.cwd(), 'data');
  this.repoDir = path.join(this.dataDir, 'repo');
  this.port = port;
  this.baseUrl = 'http://' + address + ':' + port + '/';
  console.log('CrxRepo.dataDir', this.dataDir);

  this.app = express();
  this.upload = multer({storage: multer.memoryStorage()});

  this.app.use('/repo', express.static(this.repoDir))
  this.app.use('/repo', serveIndex(this.repoDir));

  this.app.get('/updates.xml', this.onGetUpdatesXml.bind(this));
  this.app.post('/upload', this.upload.single('zippedExtension'), this.onUploadCrx.bind(this));
  this.app.get('*', this.onGetUploadPage.bind(this));
};

CrxRepo.prototype = {
  onGetUpdatesXml: function(req, res) {
    var that = this;
    var root = xmlbuilder.create('gupdate', {version: '1.0', encoding: 'UTF-8'})
      .att('xmlns', 'http://www.google.com/update2/response')
      .att('protocol', '2.0');

    async.waterfall([
      function(cb) {
        fs.readdir(that.repoDir, cb);
      },
      function(files, cb) {
        async.each(files, function(name, cb) {
          var appRepoPath = path.join(that.repoDir, name);
          var latestVersion;
          var crxPath;

          async.waterfall([
            function(cb) {
              findSubDirectories(appRepoPath, cb);
            },
            function(versions, cb) {
              if (versions.length === 0) {
                return cb('Could not find any version direcories: ' + appRepoPath);
              }
              latestVersion = versions.sort(semver.rcompare)[0];
              crxPath = path.join(appRepoPath, latestVersion, name + '.crx');
              fileExists(crxPath, cb);
            },
            function(crxExists, cb) {
              if (!crxExists) {
                return cb('Missing file: ' + crxPath);
              }

              fs.readFile(path.join(appRepoPath, 'appId.txt'), cb);
            },
            function(appId, cb) {
              var crxUrl = that.baseUrl + 'repo/' + name + '/' + latestVersion + '/' + name + '.crx';
              root.ele('app', {appid: appId}).ele('updatecheck', {codebase: crxUrl, version: latestVersion});
              cb();
            }
          ], cb);
        }, cb);
      }
    ], function(err) {
      if (err) {
        res.status(500);
        res.send(err);
      } else {
        res.type('.xml');
        res.send(root.end({ pretty: true}));
      }
    });
  },

  onUploadCrx: function(req, res) {
    var that = this;
    var name = req.body.name;
    var zippedExtension = req.file.buffer;

    var privateKeyPath = path.join(this.dataDir, 'keys',  name + '.pem');
    var appRepoPath = path.join(this.repoDir, name);

    var crx;
    var crxPath;
    var crxBuffer;
    var tempDir;
    var privateKey;

    async.waterfall([
      function(cb) {
        getPrivateKey(privateKeyPath, cb);
      },
      function(_privateKey, cb) {
        privateKey = _privateKey;
        cb();
      },
      function(cb) {
        temp.mkdir(name, cb);
      },
      function(_tempDir, cb) {
        tempDir = _tempDir
        cb();
      },
      function(cb) {
        var unzipper = unzip.Extract({path: tempDir})
        unzipper.on('close', cb);
        streamifier.createReadStream(zippedExtension).pipe(unzipper);
      },
      function(cb) {
        try {
          crx = new ChromeExtension({privateKey: privateKey});
          crx.load(tempDir)
            .then(function() { cb(null, crx); })
            .catch(function(reason) {
              cb(reason);
            });
        }
        catch (ex) {
          cb(ex);
        }
      },
      function(crx, cb) {
        if (crx.manifest.update_url !== undefined) {
          return cb('Cannot import manifest that already defines update_url');
        }

        crx.manifest.update_url = that.baseUrl + 'updates.xml';
        crxPath = path.join(appRepoPath, crx.manifest.version, name + '.crx');
        fileExists(crxPath, cb);
      },
      function(crxExists, cb) {
        if (crxExists) {
          return cb('Already published: ' + crxPath);
        }

        crx.pack()
          .then(function(crxBuffer){ cb(null, crxBuffer) })
          .catch(function(reason) { cb(reason); });
      },
      function(_crxBuffer, cb) {
        crxBuffer = _crxBuffer;
        cb();
      },
      function(cb) {
        writeFile(path.join(appRepoPath, 'appId.txt'), crx.generateAppId(), cb);
      },
      function(_appId, cb) {
        writeFile(crxPath, crxBuffer, cb);;
      }
    ], function(err) {
      rimraf(tempDir, function() {
        if (err) {
          console.error(err);
          res.status(500);
          res.send(err);
        } else {
          res.send(crx.manifest);
        }
      });
    });
  },

  onGetUploadPage: function(req, res) {
    res.send('<html><body><form action="/upload" enctype="multipart/form-data" method="post"><input type="text" name="name"><input type="file" name="zippedExtension"><input type="submit"></form></body></html>');
  },

  start: function() {
    var that = this;
    http.Server(this.app).listen(this.port, function(){
      console.log('listening on ' + that.baseUrl);
    });
  }
}

module.exports = CrxRepo;
