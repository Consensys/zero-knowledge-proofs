const sha256 = require('sha256')

function getPaymentsByDirection(direction, payments){
  var paymentsByDirection = payments.filter(function( obj ) {
      return obj.direction == direction
  })
  return paymentsByDirection
}

longToByteArray = function(valueToConvert) {
  // we want to represent the input as a 8-bytes array
  var byteArray = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

  for ( var index = byteArray.length-1; index >=0; index -- ) {
      var byte = valueToConvert & 0xff
      byteArray [ index ] = byte
      valueToConvert = (valueToConvert - byte) / 256 
  }

  return byteArray;
}

function getArray(value){
  var r_value = longToByteArray(value)
  var arr_salt = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
  return r_value.concat(arr_salt)
}

function getListOfArrays(inputArray){
  returnVal = []
  for(var i=0;i<inputArray.length;i++){
    returnVal.push(getArray(inputArray[i]))
  }
  return returnVal
}

function getListOfBuffers(inputArray){
  returnVal = []
  for(var i=0;i<inputArray.length;i++){
    returnVal.push(Buffer.from(inputArray[i]))
  }
  return returnVal
}

function getListOfSha(inputArray){
  returnVal = []
  for(var i=0;i<inputArray.length;i++){
    returnVal.push(sha256(inputArray[i], {asBytes: true}))
  }
  return returnVal
}

function generateProofInputs(startBalance, endBalance, incoming, outgoing, cb){
  var arr_startBalance = getArray(startBalance)
  var arr_endBalance = getArray(endBalance)
  var arr_incoming = getListOfArrays(incoming)
  var arr_outgoing = getListOfArrays(outgoing)

  var b_startBalance = Buffer.from(arr_startBalance)
  var b_endBalance = Buffer.from(arr_endBalance)
  var b_incoming = getListOfBuffers(arr_incoming)
  var b_outgoing = getListOfBuffers(arr_outgoing)

  var public_startBalance = sha256(b_startBalance, {asBytes: true})
  var public_endBalance = sha256(b_endBalance, {asBytes: true})
  var public_incoming = getListOfSha(b_incoming)
  var public_outgoing = getListOfSha(b_outgoing)

  var publicParameters = []
  publicParameters.push(public_startBalance.toString().replace(/,/g, ' '))
  publicParameters.push(public_endBalance.toString().replace(/,/g, ' '))
  for(var i=0;i<public_incoming.length;i++){
    publicParameters.push(public_incoming[i].toString().replace(/,/g, ' '))
  }

  for(var i=0;i<public_outgoing.length;i++){
    publicParameters.push(public_outgoing[i].toString().replace(/,/g, ' '))
  }

  var privateParameters = []
  privateParameters.push(arr_startBalance.toString().replace(/,/g, ' '))
  privateParameters.push(arr_endBalance.toString().replace(/,/g, ' '))
  for(var i=0;i<arr_incoming.length;i++){
    privateParameters.push(arr_incoming[i].toString().replace(/,/g, ' '))
  }
  for(var i=0;i<arr_outgoing.length;i++){
    privateParameters.push(arr_outgoing[i].toString().replace(/,/g, ' '))
  }

  console.log('public parameters[0]:', publicParameters[0])
  cb(publicParameters, privateParameters)
}

exports.GenerateProofInputs = generateProofInputs
