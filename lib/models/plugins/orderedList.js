var mongoose = require('mongoose'),
    ObjectId = mongoose.SchemaTypes.ObjectId;

module.exports = function(schema, options) {
  if (!options || !options.path) {
    throw new Error('Must specify a path to add the orderedList plugin');
  }

  var pathName       = options.path;
  var path           = {};
  var schemaOptions  = path[pathName] = {};
  var methodPrefix   = options.methodPrefix || (pathName.charAt(0).toUpperCase() + pathName.substr(1));
  schemaOptions.type = options.type ? [options.type.schema] : [];

  if (!schema.path(pathName)) {
    schema.add(path);
  }

  schema.methods['get' + methodPrefix] = function(id) {
    var index = (typeof id === 'number') ? id : this['indexOf' + methodPrefix](id);
    return index >= 0 ? this[pathName][index] : null;
  }

  schema.methods['add' + methodPrefix] = function(item, index) {
    // if index is supplied, add at the specified index
    if (index != null) {
      if (index < 0 || index > this[pathName].length) {
        throw new Error(methodPrefix + ' index ' + index + ' is out of range');
      }
      this[pathName].splice(index, 0, item);
    }
    else {
      this[pathName].push(item);
    }

    return this;
  };

  schema.methods['update' + methodPrefix + 'Index'] = function(oldIndex, newIndex) {
    if (oldIndex < 0 || oldIndex > this[pathName].length-1) {
      // SECURITY: methodPrefix replaces the previously-undefined `upperPathName`
      // SECURITY: identifier (typo). The undefined reference would have caused a
      // SECURITY: ReferenceError to be thrown instead of the intended Error message,
      // SECURITY: degrading the bounds-check defense (CWE-129 Improper Validation of
      // SECURITY: Array Index) to a less-descriptive crash. Mirrors the adjacent line
      // SECURITY: 44 pattern (`methodPrefix + ' index ' + newIndex + ...`) and the
      // SECURITY: line 28 pattern in `add{methodPrefix}` for consistent error messages.
      // SECURITY: Fixes ESLint no-undef error per AAP §0.5.2 Strategy I / R9 audit findings.
      throw new Error(methodPrefix + ' index ' + oldIndex + ' is out of range');
    }
    if (newIndex < 0 || newIndex > this[pathName].length-1) {
      throw new Error(methodPrefix + ' index ' + newIndex + ' is out of range');
    }

    var item = this[pathName][oldIndex];

    this[pathName].splice(oldIndex, 1);
    this[pathName].splice(newIndex, 0, item);

    return this;
  };

  // idIndex allows you to find the index of a document in an embedded document array
  // Accepted id formats are:
  //   String
  //   ObjectId
  //   {id:String}
  //   {id:ObjectId}
  //   {_id:String}
  //   {_id:ObjectId}
  //   Document
  // Returns -1 if not found
  schema.methods['indexOf' + methodPrefix] = function(item) {
    var id;

    if (item instanceof mongoose.Types.ObjectId || item instanceof mongoose.Schema.ObjectId) {
      id = item.toString();
    }
    else if (typeof item === 'string') {
      id = item;
    }
    else {
      id = (item.id || item._id).toString();
    }

    for (var i = 0, l = this[pathName].length; i < l; i++) {
      if (id === this[pathName][i].id) {
        return i;
      }
    }

    return -1;
  };
};
