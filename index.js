var prompt = require('prompt');
var fs = require('fs');

const {spawn} = require('child_process');
const sha256 = require('sha256')

var startBalance = 0
var endBalance = 0
var incoming1 = 0
var incoming2 = 0
var outgoing1 = 0
var outgoing2 = 0

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

function generateProofInputs(fileSuffix, cb){

  var arr_startBalance = getArray(startBalance)
  var arr_endBalance = getArray(endBalance)
  var arr_incoming1 = getArray(incoming1)
  var arr_incoming2 = getArray(incoming2)
  var arr_outgoing1 = getArray(outgoing1)
  var arr_outgoing2 = getArray(outgoing2)

  var b_startBalance = Buffer.from(arr_startBalance)
  var b_endBalance = Buffer.from(arr_endBalance)
  var b_incoming1 = Buffer.from(arr_incoming1)
  var b_incoming2 = Buffer.from(arr_incoming2)
  var b_outgoing1 = Buffer.from(arr_outgoing1)
  var b_outgoing2 = Buffer.from(arr_outgoing2)

  var public_startBalance = sha256(b_startBalance, {asBytes: true})
  var public_endBalance = sha256(b_endBalance, {asBytes: true})
  var public_incoming1 = sha256(b_incoming1, {asBytes: true})
  var public_incoming2 = sha256(b_incoming2, {asBytes: true})
  var public_outgoing1 = sha256(b_outgoing1, {asBytes: true})
  var public_outgoing2 = sha256(b_outgoing2, {asBytes: true})

  var publicParameters = public_startBalance.toString().replace(/,/g, ' ') + "\n"
  publicParameters += public_endBalance.toString().replace(/,/g, ' ') + "\n"
  publicParameters += public_incoming1.toString().replace(/,/g, ' ') + "\n"

  if(fileSuffix=="multi"){
    publicParameters += public_incoming2.toString().replace(/,/g, ' ') + "\n"
  }

  publicParameters += public_outgoing1.toString().replace(/,/g, ' ') + "\n"
  if(fileSuffix=="multi"){
    publicParameters += public_outgoing2.toString().replace(/,/g, ' ')
  }

  var privateParameters = arr_startBalance.toString().replace(/,/g, ' ') + "\n"
  privateParameters += arr_endBalance.toString().replace(/,/g, ' ') + "\n"
  privateParameters += arr_incoming1.toString().replace(/,/g, ' ') + "\n"
  if(fileSuffix=="multi"){
    privateParameters += arr_incoming2.toString().replace(/,/g, ' ') + "\n"
  }
  privateParameters += arr_outgoing1.toString().replace(/,/g, ' ') + "\n"
  if(fileSuffix=="multi"){
    privateParameters += arr_outgoing2.toString().replace(/,/g, ' ')
  }

  fs.writeFile('publicInputParameters_' + fileSuffix, publicParameters, function(errPublic) {
    if(errPublic) {
      cb('An error occured generating the public input parameters',errPublic)
    } else {
      fs.writeFile('privateInputParameters_' + fileSuffix, privateParameters, function(errPrivate) {
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
    console.log('Please enter the amounts that are being paid')
    prompt.get(['incoming1', 'incoming2','outgoing1', 'outgoing2'], function(err, paymentAmountInputs){
      incoming1 = parseInt(paymentAmountInputs.incoming1)
      incoming2 = parseInt(paymentAmountInputs.incoming2)
      outgoing1 = parseInt(paymentAmountInputs.outgoing1)
      outgoing2 = parseInt(paymentAmountInputs.outgoing2)
      endBalance = startBalance + incoming1 + incoming2 - outgoing1 - outgoing2

      generateProofInputs("multi", function(msg1, err1){
        if(err1){
          console.log(msg1, err1)
          cb()
        } else {
          handleExecuteProgram('./payment_multi_generate_proof', 'Loading Proving Key from file... (this takes a few seconds)', '', 'The proof generation failed\n\n', function(msgGenerateProof){
            if(msgGenerateProof){
              console.log('\n' + msgGenerateProof)
            }
            cb()
          })
        }
      })
    })
  })
}

function handleGenerateSinglePaymentProof(cb){
  fs.unlink('proof1', function(error) {
    console.log('Please enter the amounts that are being paid')
    prompt.get(['incoming', 'outgoing'], function(err, paymentAmountInputs){
      incoming1 = parseInt(paymentAmountInputs.incoming)
      incoming2 = 0
      outgoing1 = parseInt(paymentAmountInputs.outgoing)
      outgoing2 = 0
      endBalance = startBalance + incoming1 - outgoing1

      generateProofInputs("single", function(msg1, err1){
        if(err1){
          console.log(msg1, err1)
          cb()
        } else {
          handleExecuteProgram('./payment_in_out_generate_proof', 'Loading Proving Key from file... (this takes a few seconds)', '', 'The proof generation failed\n\n', function(msgGenerateProof){
            if(msgGenerateProof){
              console.log('\n' + msgGenerateProof)
            }
            cb()
          })
        }
      })
    })
  })
}

function handleSinglePayments(){
  console.log('Start balance:', startBalance)
  console.log('Incoming payment:', incoming1)
  console.log('Outgoing payment:', outgoing1)
  console.log('End balance:', endBalance)
  console.log('')
  console.log('Please select an option:\n1) Create a new key pair\n2) Generate a single-payment proof\n3) Verify single-payment proof\n0) Quit')
  prompt.get(['option'], function(err, answer){
    if(answer.option == 1){
      handleExecuteProgram('./payment_in_out_generate_keypair', 'Generating key pair...', 'The key pair has been generated and the keys written to files (provingKey and verificationKey)', 'The key pair failed\n\n', function(){
        handleSinglePayments()
      })
    } else if (answer.option == 2){
      handleGenerateSinglePaymentProof(function(){
        handleSinglePayments()
      })
    } else if(answer.option == 3){
      handleExecuteProgram('./payment_in_out_verify_proof', '', '', 'The proof verification failed\n\n', function(verifyErr){
        if(verifyErr){
          console.log(verifyErr)
          handleSinglePayments()
        } else {
          console.log('Verification was succesful')
          startBalance = endBalance
          incoming1 = 0
          incoming2 = 0
          outgoing1 = 0
          outgoing2 = 0
          
          handleSinglePayments()
        }
      })
    } else {
      console.log('Quiting...')
    }
  })
}

function handleMultiplePayments(){
  console.log('Start balance:', startBalance)
  console.log('Total incoming payments:', (incoming1 + incoming2))
  console.log('Total outgoing payments:', (outgoing1 + outgoing2))
  console.log('End balance:', endBalance)
  console.log('')
  console.log('Please select an option:\n1) Create a new key pair\n2) Generate a multi-payment proof\n3) Verify multi-payment proof\n0) Quit')
  prompt.get(['option'], function(err, answer){
    if(answer.option == 1){
      handleExecuteProgram('./payment_multi_generate_keypair', 'Generating key pair...', 'The key pair has been generated and the keys written to files (provingKey_multi and verificationKey_multi)', 'The key pair failed\n\n', function(){
        handleMultiplePayments()
      })
    } else if (answer.option == 2){
      handleGenerateMultiPaymentProof(function(){
        handleMultiplePayments()
      })
    } else if(answer.option == 3){
      handleExecuteProgram('./payment_multi_verify_proof', '', '', 'The proof verification failed\n\n', function(verifyErr){
        if(verifyErr){
          console.log(verifyErr)
          handleMultiplePayments()
        } else {
          console.log('Verification was succesful')
          startBalance = endBalance
          incoming1 = 0
          incoming2 = 0
          outgoing1 = 0
          outgoing2 = 0
          
          handleMultiplePayments()
        }
      })
    } else {
      console.log('Quiting...')
    }
  })
}

function handleStartSelection(){
  console.log('')
  console.log('Please select an option:\n1) Single payment in and single payment out\n2) Multiple payments in and multiple payments out\n0) Quit')
  prompt.get(['option'], function(err, answer){
    if(answer.option == 1){
      handleSinglePayments()
    } else if (answer.option == 2){
      handleMultiplePayments()
    } else {
      console.log('Quiting...')
    }
  })
}

handleStartSelection()
