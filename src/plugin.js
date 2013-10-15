var bcrypt = require("bcrypt");

module.exports = function(schema, options) {
  var fields = {
    password: {
      type: String,
      required: true
    }
  };


  schema.add(fields);


  schema.method("setPassword", function(callback) {
    var self = this;

    bcrypt.genSalt(10, function(err, salt) {
      if (err) {
        return callback(err);
      }

      bcrypt.hash(self.password, salt, function(err, hash) {
        if (err) {
          return callback(err);
        }
        self.password = hash;
        return callback(null, hash);
      });
    });
  });


  schema.method("authenticate", function(candidatePassword, callback) {
    bcrypt.compare(candidatePassword, this.password, function(err, isMatch) {
      return callback(err, isMatch);
    });
  });
};
