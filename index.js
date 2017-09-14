var prompt = require('prompt');
var fs = require('fs');

const {spawn} = require('child_process');
const sha256 = require('sha256')

var startBalance = 0
var endBalance = 0
var incoming = 0
var outgoing = 0

if(process.argv.length!=3){
  console.log("you need to set your start balance.  Run the application using node index.js startBalance=1000")
  return 1
}

process.argv.forEach(function (val, index, array) {
  if(val.startsWith("startBalance")){
    startBalance = parseInt(val.split("=")[1])
    endBalance = startBalance
  }
});

function getMatches(string, regex) {
  var matches = [];
  var match;
  while (match = regex.exec(string)) {
    matches.push(match[0]);
  }
  return matches;
}

function handleExecuteProgram(programName, msgStart, msgEnd, msgError, cb){
  console.log(msgStart)

  var succesfullyCompleted=true
  const runCommand = spawn(programName)

  runCommand.stdout.on('data', (data) => {
    dataString = data.toString()
    if(dataString.indexOf('System not satisfied!')>-1){
      succesfullyCompleted = false
    }
    if(data.indexOf('Compute the proof')>-1){
      if(data.indexOf('(enter)')>-1){
        console.log('\nProof generation started')
      } else {
        var matches = getMatches(dataString, /[0-9].[0-9]*s/g)
        var noSecs = matches[2]
        console.log('\nProof generation ended:', noSecs)
      }
    } else {
      process.stdout.write('.')
    }
  })

  runCommand.stderr.on('data', (data) => {
    console.log(data.toString())
    succesfullyCompleted = false
  })

  runCommand.on('close', (code) => {
    console.log()
    if(code=='1' || !succesfullyCompleted){
      cb(msgError)
    } else {
      cb(null)
    }
  })
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

function generateProofInputs(cb){

  var arr_startBalance = getArray(startBalance)
  var arr_endBalance = getArray(endBalance)
  var arr_incoming = getArray(incoming)
  var arr_outgoing = getArray(outgoing)

  var b_startBalance = Buffer.from(arr_startBalance)
  var b_endBalance = Buffer.from(arr_endBalance)
  var b_incoming = Buffer.from(arr_incoming)
  var b_outgoing = Buffer.from(arr_outgoing)

  var public_startBalance = sha256(b_startBalance, {asBytes: true})
  var public_endBalance = sha256(b_endBalance, {asBytes: true})
  var public_incoming = sha256(b_incoming, {asBytes: true})
  var public_outgoing = sha256(b_outgoing, {asBytes: true})

  var publicParameters = public_startBalance.toString().replace(/,/g, ' ') + "\n"
  publicParameters += public_endBalance.toString().replace(/,/g, ' ') + "\n"
  publicParameters += public_incoming.toString().replace(/,/g, ' ') + "\n"
  publicParameters += public_outgoing.toString().replace(/,/g, ' ')

  var privateParameters = arr_startBalance.toString().replace(/,/g, ' ') + "\n"
  privateParameters += arr_endBalance.toString().replace(/,/g, ' ') + "\n"
  privateParameters += arr_incoming.toString().replace(/,/g, ' ') + "\n"
  privateParameters += arr_outgoing.toString().replace(/,/g, ' ')

  fs.writeFile('publicInputParameters', publicParameters, function(errPublic) {
    if(errPublic) {
      cb('An error occured generating the public input parameters',errPublic)
    } else {
      fs.writeFile('privateInputParameters', privateParameters, function(errPrivate) {
        if(errPrivate) {
          cb('An error occured generating the private input parameters',errPrivate)
        } else {
          cb('', null)
        }
      }) 
    }
  }) 

}

function handleGenerateMultiPaymentProof(cb){
  fs.unlink('proof1', function(error) {
  fs.unlink('proof2', function(error) {
    console.log('Please enter the amounts that are being paid')
    prompt.get(['incoming', 'outgoing'], function(err, paymentAmountInputs){
      incoming = parseInt(paymentAmountInputs.incoming)
      outgoing = parseInt(paymentAmountInputs.outgoing)
      endBalance = startBalance + incoming - outgoing

      generateProofInputs(function(msg1, err1){
        if(err1){
          console.log(msg1, err1)
          cb()
        } else {
          handleExecuteProgram('./generateProof', 'Loading Proving Key from file... (this takes a few seconds)', '', 'The proof generation failed\n\n', function(msgGenerateProof){
            if(msgGenerateProof){
              console.log('\n' + msgGenerateProof)
            }
            cb()
          })
        }
      })
    })
  })
  })
}

function handleInput(){
  console.log('Start balance:', startBalance)
  console.log('Total incoming payments:', incoming)
  console.log('Total outgoing payments:', outgoing)
  console.log('End balance:', endBalance)
  console.log('')
  console.log('Please select an option:\n1) Create a new key pair\n2) Generate a multi-payment proof\n3) Verify multi-payment proof\n0) Quit')
  prompt.get(['option'], function(err, answer){
    if(answer.option == 1){
      handleExecuteProgram('./generateKeyPair', 'Generating key pair...', 'The key pair has been generated and the keys written to files (provingKey and verificationKey)', 'The key pair failed\n\n', function(){
        handleInput()
      })
    } else if (answer.option == 2){
      handleGenerateMultiPaymentProof(function(){
        handleInput()
      })
    } else if(answer.option == 3){
      handleExecuteProgram('./verifyProof', '', '', 'The proof verification failed\n\n', function(verifyErr){
        if(verifyErr){
          console.log(verifyErr)
          handleInput()
        } else {
          console.log('Verification was succesful')
          startBalance = endBalance
          incoming = 0
          outgoing = 0
          
          handleInput()
        }
      })
    } else {
      console.log('Quiting...')
    }
  })
}

handleInput()
